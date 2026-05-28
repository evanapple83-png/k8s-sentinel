/**
 * Unit tests for tunnel/argus.ts — the v3 ARGUS bridge.
 *
 * Two layers:
 *   1. Pure mapping (`mapToPostureSnapshot`): canned v3 JSON → valid wire
 *      PostureSnapshot. Hits the schema's `parse()` so any drift between
 *      mapper and wire contract fails here.
 *   2. Subprocess plumbing (`runArgusScan`): an injected spawn stub that
 *      writes a fixture `report.json` and exits 0. Covers the happy path,
 *      missing JSON, and non-zero exit with empty stdout.
 *
 * No real Python interpreter, no scanner binaries, no cluster.
 */
import { mkdtempSync, writeFileSync, rmSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { EventEmitter } from 'node:events';
import { describe, expect, it } from 'vitest';

import { PostureSnapshotSchema } from '@k8s-sentinel/relay-protocol';
import {
  ArgusExitError,
  ArgusOutputError,
  mapToPostureSnapshot,
  runArgusScan,
  type ArgusReportJson,
} from './argus.js';

// ---------------------------------------------------------------------------
// Fixtures — shaped like a real v3 report.json (cli._build_json_report).
// ---------------------------------------------------------------------------

function fixtureReport(): ArgusReportJson {
  return {
    cluster: 'prod-eu-1',
    scannedAt: '2026-05-28T09:14:00Z',
    riskScore: 100,
    intel: { kev_count: 1607, version: '2026.05.27', source: 'live:cisa-kev' },
    reachableJewels: [
      'secret:payments/db-credentials',
      'secret:ci/registry-token',
      'CLUSTER-ADMIN',
      'CLOUD-ADMIN',
    ],
    paths: {
      'secret:payments/db-credentials': [
        [
          'ext:internet',
          'wl:payments/invoice-api',
          'exploit CVE-2026-31337 (internet-exposed)',
          { type: 'patch', ref: 'CVE-2026-31337', workload: 'payments/invoice-api' },
          false,
        ],
        ['wl:payments/invoice-api', 'sa:payments/invoice-sa', 'uses ServiceAccount token', null, false],
        [
          'sa:payments/invoice-sa',
          'secret:payments/db-credentials',
          'RBAC: can read Secret',
          { type: 'rbac-least-privilege', sa: 'payments/invoice-sa', what: 'secrets' },
          false,
        ],
      ],
      'CLUSTER-ADMIN': [
        ['ext:internet', 'wl:ci/runner', 'exploit CVE-2026-40002 (lateral)', null, true],
        ['wl:ci/runner', 'sa:ci/ci-deployer', 'uses ServiceAccount token', null, false],
        [
          'sa:ci/ci-deployer',
          'CLUSTER-ADMIN',
          'RBAC: create/exec pods → mount any SA → cluster-admin',
          { type: 'rbac-least-privilege', sa: 'ci/ci-deployer', what: 'escalation' },
          false,
        ],
      ],
    },
    chokePoints: [
      {
        control: { type: 'patch', ref: 'CVE-2026-31337', workload: 'payments/invoice-api' },
        breaks: 4,
        targets: ['secret:payments/db-credentials', 'CLUSTER-ADMIN', 'CLOUD-ADMIN', 'secret:ci/registry-token'],
      },
      {
        control: { type: 'rbac-least-privilege', sa: 'ci/ci-deployer', what: 'escalation' },
        breaks: 1,
        targets: ['CLUSTER-ADMIN'],
      },
    ],
    findings: [
      {
        id: 'trivy-001',
        cve: 'CVE-2026-31337',
        title: 'RCE in libfoo < 2.1',
        target: 'payments/invoice-api',
        kev: true,
        ransomware: true,
        epss: 0.92,
        cvss: 9.8,
        exposure: 'open',
        confidence: 'high',
        decision: 'Act',
        score: 100,
        reaches: ['secret'],
      },
      {
        id: 'trivy-002',
        cve: 'CVE-2026-31337',
        title: 'RCE in libfoo < 2.1',
        target: 'batch/report-worker',
        kev: true,
        ransomware: true,
        epss: 0.92,
        cvss: 9.8,
        exposure: 'small',
        confidence: 'n/a',
        decision: 'Track*',
        score: 3,
        reaches: [],
      },
    ],
    workloads: [
      { id: 'payments/invoice-api', kind: 'Deployment', namespace: 'payments', image: 'acme/invoice-api:1.2.3' },
      { id: 'batch/report-worker', kind: 'Deployment', namespace: 'batch', image: 'acme/invoice-api:1.2.3' },
      { id: 'ci/runner', kind: 'Deployment', namespace: 'ci', image: 'acme/ci-runner:4.0' },
    ],
    activeFindings: [
      {
        id: 'trivy-001',
        source: 'trivy',
        type: 'cve',
        cve: 'CVE-2026-31337',
        severity: 'critical',
        target: 'payments/invoice-api',
        title: 'RCE in libfoo < 2.1',
      },
      {
        id: 'trivy-002',
        source: 'trivy',
        type: 'cve',
        cve: 'CVE-2026-31337',
        severity: 'critical',
        target: 'batch/report-worker',
        title: 'RCE in libfoo < 2.1',
      },
    ],
    metadata: { scanners: [], threat_intel: null },
  };
}

// ---------------------------------------------------------------------------
// Pure mapping
// ---------------------------------------------------------------------------

describe('mapToPostureSnapshot', () => {
  it('produces a snapshot that passes the wire schema', () => {
    const snap = mapToPostureSnapshot(fixtureReport());
    // The schema is the trust boundary; any oversize / wrong-enum / missing
    // field would throw here.
    expect(() => PostureSnapshotSchema.parse(snap)).not.toThrow();
  });

  it('maps SSVC decision → wire severity', () => {
    const snap = mapToPostureSnapshot(fixtureReport());
    const byId = new Map(snap.findings.map((f) => [f.id, f]));
    expect(byId.get('trivy-001')?.severity).toBe('critical'); // Act
    expect(byId.get('trivy-002')?.severity).toBe('low'); //     Track*
  });

  it('uses the workload kind from the inventory slim view', () => {
    const snap = mapToPostureSnapshot(fixtureReport());
    const f = snap.findings.find((x) => x.id === 'trivy-001');
    expect(f?.resource.kind).toBe('Deployment');
    expect(f?.resource.namespace).toBe('payments');
    expect(f?.resource.name).toBe('invoice-api');
    expect(f?.resource.image).toBe('acme/invoice-api:1.2.3');
  });

  it('preserves source/ruleId from the raw scanner finding', () => {
    const snap = mapToPostureSnapshot(fixtureReport());
    const f = snap.findings.find((x) => x.id === 'trivy-001');
    expect(f?.source).toBe('trivy');
    expect(f?.ruleId).toBe('CVE-2026-31337');
  });

  it('smuggles v3 intel into the description field until the wire widens', () => {
    const snap = mapToPostureSnapshot(fixtureReport());
    const f = snap.findings.find((x) => x.id === 'trivy-001');
    expect(f?.description).toContain('KEV: yes');
    expect(f?.description).toContain('Ransomware: yes');
    expect(f?.description).toContain('SSVC: Act');
  });

  it('emits one WireAttackPath per reachable crown jewel with steps in order', () => {
    const snap = mapToPostureSnapshot(fixtureReport());
    expect(snap.paths).toHaveLength(2);
    const secretPath = snap.paths.find((p) => p.narrative.includes('db-credentials'));
    expect(secretPath?.entryPoint).toBe('internet');
    expect(secretPath?.steps).toHaveLength(3);
    expect(secretPath?.steps[0]?.kind).toBe('workload');
    expect(secretPath?.steps[secretPath.steps.length - 1]?.kind).toBe('secret');
  });

  it('flags inferred lateral-movement steps in the detail', () => {
    const snap = mapToPostureSnapshot(fixtureReport());
    const clusterPath = snap.paths.find((p) => p.narrative.includes('cluster-admin'));
    expect(clusterPath?.steps[0]?.detail).toMatch(/\(inferred\)/);
  });

  it('maps choke-points to manual remediations, top breaks → critical', () => {
    const snap = mapToPostureSnapshot(fixtureReport());
    expect(snap.remediations).toHaveLength(2);
    const top = snap.remediations[0]!;
    expect(top.kind).toBe('manual');
    expect(top.severity).toBe('critical'); //  breaks=4, total=4 → all paths
    expect(top.title).toMatch(/Patch CVE-2026-31337/);
    expect(top.rationale).toMatch(/Eliminates 4 of 4/);
    expect(top.priority).toBe(4);
  });

  it('builds a WireRun summary carrying the live KEV catalog stats', () => {
    const snap = mapToPostureSnapshot(fixtureReport());
    expect(snap.run.engine).toBe('argus-v3');
    expect(snap.run.riskScore).toBe(100);
    expect(snap.run.findingCount).toBe(2);
    expect(snap.run.pathCount).toBe(2);
    expect(snap.run.summary).toContain('KEV');
    expect(snap.run.summary).toContain('1607');
    expect(snap.run.summary).toContain('2026.05.27');
    expect(snap.run.summary).toContain('crown-jewel');
  });

  it('falls back gracefully when activeFindings / workloads are absent', () => {
    const report = fixtureReport();
    delete report.activeFindings;
    delete report.workloads;
    const snap = mapToPostureSnapshot(report);
    expect(() => PostureSnapshotSchema.parse(snap)).not.toThrow();
    const f = snap.findings[0]!;
    // Without raw findings, source defaults to "argus" and resource.kind to "Workload".
    expect(f.source).toBe('argus');
    expect(f.resource.kind).toBe('Workload');
  });
});

// ---------------------------------------------------------------------------
// Subprocess plumbing — spawn stub
// ---------------------------------------------------------------------------

/** Mimic the relevant slice of node:child_process.ChildProcess. */
function fakeProcess(): {
  proc: EventEmitter & { stdout: EventEmitter; stderr: EventEmitter; kill: () => void };
  exit: (code: number, signal?: NodeJS.Signals | null) => void;
} {
  const proc = Object.assign(new EventEmitter(), {
    stdout: new EventEmitter(),
    stderr: new EventEmitter(),
    kill: () => undefined,
  });
  return {
    proc,
    exit: (code, signal = null) =>
      setImmediate(() => proc.emit('exit', code, signal)),
  };
}

/** Resolve when runArgusScan's spawn is called; the test can then exit it. */
type SpawnStub = ReturnType<typeof makeSpawnStub>;
function makeSpawnStub(handler: (cwd: string, outDir: string, args: string[]) => Promise<number>) {
  const calls: Array<{ cwd: string; args: string[] }> = [];
  const impl = ((_cmd: string, args: readonly string[], opts: { cwd?: string }) => {
    const cwd = opts.cwd ?? '';
    calls.push({ cwd, args: args as string[] });
    const outDir = (args as string[])[(args as string[]).indexOf('--out') + 1] ?? '';
    const { proc, exit } = fakeProcess();
    void (async () => {
      try {
        const code = await handler(cwd, outDir, args as string[]);
        proc.stdout.emit('data', Buffer.from(''));
        exit(code);
      } catch (err) {
        proc.emit('error', err as Error);
      }
    })();
    return proc as unknown;
  }) as unknown as typeof import('node:child_process').spawn;
  return { impl, calls };
}

function writeReport(outDir: string, report: ArgusReportJson) {
  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'report.json'), JSON.stringify(report));
}

describe('runArgusScan', () => {
  it('happy path: spawns, reads report.json, returns valid snapshot', async () => {
    const stub = makeSpawnStub(async (_cwd, outDir) => {
      writeReport(outDir, fixtureReport());
      return 0;
    });
    const snap = await runArgusScan({
      argusCwd: tmpdir(),         // we don't actually exec anything in stub
      spawnImpl: stub.impl,
      clusterName: 'kind-smoke',
    });
    expect(snap.run.findingCount).toBe(2);
    expect(stub.calls.length).toBe(1);
    const args = stub.calls[0]!.args;
    expect(args).toContain('--in-cluster');
    expect(args).toContain('--cluster-name');
    expect(args[args.indexOf('--cluster-name') + 1]).toBe('kind-smoke');
    expect(args).toContain('--quiet');
  });

  it('passes through --accepted-risks, --no-network, --images-only when set', async () => {
    const stub = makeSpawnStub(async (_cwd, outDir) => {
      writeReport(outDir, fixtureReport());
      return 0;
    });
    await runArgusScan({
      argusCwd: tmpdir(),
      spawnImpl: stub.impl,
      acceptedRisksDir: '/etc/argus/accepted-risks',
      noNetwork: true,
      imagesOnly: true,
      inCluster: false,
      kubeconfig: '/home/argus/.kube/config',
    });
    const args = stub.calls[0]!.args;
    expect(args).toContain('--accepted-risks');
    expect(args[args.indexOf('--accepted-risks') + 1]).toBe('/etc/argus/accepted-risks');
    expect(args).toContain('--no-network');
    expect(args).toContain('--images-only');
    expect(args).not.toContain('--in-cluster');
    expect(args).toContain('--kubeconfig');
  });

  it('throws ArgusOutputError when report.json is missing', async () => {
    const stub = makeSpawnStub(async () => 0); // don't write anything
    await expect(runArgusScan({ argusCwd: tmpdir(), spawnImpl: stub.impl })).rejects.toBeInstanceOf(
      ArgusOutputError,
    );
  });

  it('throws ArgusExitError when subprocess exits non-zero with empty stdout', async () => {
    const stub = makeSpawnStub(async () => 2);
    await expect(runArgusScan({ argusCwd: tmpdir(), spawnImpl: stub.impl })).rejects.toBeInstanceOf(
      ArgusExitError,
    );
  });

  it('cleans up the temp out dir even on failure', async () => {
    // Capture the outDir by intercepting before failing.
    let observedOutDir = '';
    const stub: SpawnStub = makeSpawnStub(async (_cwd, outDir) => {
      observedOutDir = outDir;
      // Don't write a report → triggers ArgusOutputError.
      return 0;
    });
    await expect(runArgusScan({ argusCwd: tmpdir(), spawnImpl: stub.impl })).rejects.toBeInstanceOf(
      ArgusOutputError,
    );
    expect(observedOutDir).not.toBe('');
    expect(existsSync(observedOutDir)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Bonus: belt-and-braces — a hand-built tmpdir doesn't leak into other tests.
// ---------------------------------------------------------------------------

describe('hygiene', () => {
  it('mkdtempSync sanity (catches a Node-version regression in CI)', () => {
    const d = mkdtempSync(join(tmpdir(), 'argus-test-'));
    try {
      expect(existsSync(d)).toBe(true);
    } finally {
      rmSync(d, { recursive: true, force: true });
    }
  });
});
