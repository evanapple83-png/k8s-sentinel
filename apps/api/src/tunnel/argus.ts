/**
 * apps/api/src/tunnel/argus.ts — spawn the Python ARGUS pipeline and map its v3
 * attack-graph report onto the relay's wire PostureSnapshot.
 *
 * This is the bridge between the TS tunnel-client (PID 1 in the agent pod) and
 * the deterministic v3 engine that lives under `argus/`. The TS side stays the
 * read-only durable WSS connection; ARGUS does the actual scanning + scoring
 * + correlation as a short-lived subprocess invoked when a `scan` command
 * arrives.
 *
 * Trust boundary preserved: the output is validated against
 * `PostureSnapshotSchema` before this function returns. Any mapping mistake
 * (oversize string, wrong enum, missing field) fails IN-CLUSTER, never at the
 * relay.
 *
 * v3 fields the existing wire schema doesn't yet carry (KEV, ransomware, EPSS,
 * SSVC decision, choke-point analysis, live threat-intel catalog version) are
 * smuggled into the closest existing fields where possible:
 *   - SSVC decision  →  WireFinding.severity (Act→critical, Attend→high,
 *                       Track→medium, Track*→low; preserves the colour the UI
 *                       already understands)
 *   - choke-points   →  WireRemediation[]   (kind: 'manual'; ARGUS doesn't
 *                       produce diffs — those are PR-bundles)
 *   - intel banner   →  WireRun.summary     ("CISA KEV v… · N known-exploited")
 *
 * Fase 3 widens the wire schema with first-class fields for the above; the
 * mapping below collapses to a strict 1:1 then.
 */
import { spawn } from 'node:child_process';
import { promises as fs } from 'node:fs';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  PostureSnapshotSchema,
  type PostureSnapshot,
  type WireAttackPath,
  type WireAttackStep,
  type WireFinding,
  type WireRemediation,
  type WireRun,
  type Severity,
} from '@k8s-sentinel/relay-protocol';

// --- Public API -------------------------------------------------------------

export interface RunArgusOptions {
  /** Cluster identifier carried in the run summary. Default: 'cluster'. */
  clusterName?: string;
  /** Use in-cluster SA token. Default true (the only mode used in production). */
  inCluster?: boolean;
  /** Kubeconfig path (only used when inCluster=false; e.g. dev/CI). */
  kubeconfig?: string;
  /** Kube context (only used when inCluster=false). */
  context?: string;
  /** Directory of accepted-risk .md files. If unset, no AR policies are loaded. */
  acceptedRisksDir?: string;
  /** Suppress the live CISA KEV fetch (use cache + override only). Default false. */
  noNetwork?: boolean;
  /** Run only Trivy on workload images; skip kube-bench + Kubescape. Default false. */
  imagesOnly?: boolean;
  /** Maximum runtime before we kill the subprocess. Default 5 min. */
  timeoutMs?: number;
  /** Inject a custom spawner for tests. */
  spawnImpl?: typeof spawn;
  /** Override the directory containing the `argus/` Python package. */
  argusCwd?: string;
  /** Inject a logger; defaults to a no-op. */
  log?: (level: 'info' | 'warn' | 'error', msg: string, meta?: Record<string, unknown>) => void;
}

/**
 * Run a single scan: spawn `python3 -m argus.cli scan …`, read its
 * `report.json`, and map it to a validated PostureSnapshot.
 *
 * Throws on:
 *   - missing `python3` / ARGUS package    (`ArgusSpawnError`)
 *   - non-zero exit + empty stdout         (`ArgusExitError`)
 *   - missing or unparseable `report.json` (`ArgusOutputError`)
 *   - wire-schema validation failure       (zod error from `parse`)
 */
export async function runArgusScan(opts: RunArgusOptions = {}): Promise<PostureSnapshot> {
  const log = opts.log ?? (() => {});
  const outDir = await mkdtemp(join(tmpdir(), 'argus-out-'));
  try {
    const cwd = opts.argusCwd ?? (await resolveArgusCwd());
    const args = buildArgs({ ...opts, outDir });
    log('info', 'argus: spawning subprocess', { cwd, args });

    const exit = await runChild(opts.spawnImpl ?? spawn, cwd, args, opts.timeoutMs ?? 5 * 60_000, log);
    if (exit.code !== 0 && !exit.stdout.trim()) {
      throw new ArgusExitError(exit.code, exit.signal, exit.stderr);
    }

    const reportPath = join(outDir, 'report.json');
    let raw: string;
    try {
      raw = await readFile(reportPath, 'utf-8');
    } catch (err) {
      throw new ArgusOutputError(`report.json missing at ${reportPath}: ${(err as Error).message}`);
    }
    let report: ArgusReportJson;
    try {
      report = JSON.parse(raw) as ArgusReportJson;
    } catch (err) {
      throw new ArgusOutputError(`report.json is not valid JSON: ${(err as Error).message}`);
    }

    const snapshot = mapToPostureSnapshot(report);
    return PostureSnapshotSchema.parse(snapshot);
  } finally {
    // Always clean up the tmpdir — report.json + report.md are ephemeral; the
    // snapshot we just built IS the long-lived projection of the run.
    await rm(outDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

/** Decision-style mapping of the v3 ARGUS JSON into the wire PostureSnapshot. */
export function mapToPostureSnapshot(report: ArgusReportJson): PostureSnapshot {
  // Index inputs once so the per-finding map is O(1).
  const workloadById = new Map<string, ArgusWorkload>();
  for (const w of report.workloads ?? []) workloadById.set(w.id, w);
  const rawById = new Map<string, ArgusActiveFinding>();
  for (const f of report.activeFindings ?? []) rawById.set(f.id, f);

  const findings = (report.findings ?? []).map((f) => mapFinding(f, rawById, workloadById));
  const paths = mapPaths(report.paths ?? {}, workloadById);
  const remediations = mapChokePoints(report.chokePoints ?? [], report.reachableJewels ?? []);
  const run = buildRunRecord(report);

  return { run, findings, paths, remediations, audit: [] };
}

// --- Spawn + run-to-completion ---------------------------------------------

interface ChildExit {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

async function runChild(
  spawner: typeof spawn,
  cwd: string,
  args: string[],
  timeoutMs: number,
  log: NonNullable<RunArgusOptions['log']>,
): Promise<ChildExit> {
  return await new Promise<ChildExit>((res, rej) => {
    let proc;
    try {
      proc = spawner('python3', args, { cwd, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (err) {
      return rej(new ArgusSpawnError((err as Error).message));
    }
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    proc.stdout?.on('data', (b: Buffer) => stdoutChunks.push(b));
    proc.stderr?.on('data', (b: Buffer) => {
      stderrChunks.push(b);
      // Forward each line to the agent's logger so operators see ARGUS
      // progress in pod logs — without dumping it on the wire.
      for (const line of b.toString('utf-8').split('\n')) {
        const trimmed = line.trim();
        if (trimmed) log('info', `argus: ${trimmed}`);
      }
    });

    const timer = setTimeout(() => {
      log('error', 'argus: timeout, killing subprocess', { timeoutMs });
      proc.kill('SIGTERM');
      setTimeout(() => proc.kill('SIGKILL'), 5_000).unref();
    }, timeoutMs);
    timer.unref?.();

    proc.on('error', (err) => {
      clearTimeout(timer);
      rej(new ArgusSpawnError(err.message));
    });
    proc.on('exit', (code, signal) => {
      clearTimeout(timer);
      res({
        code,
        signal,
        stdout: Buffer.concat(stdoutChunks).toString('utf-8'),
        stderr: Buffer.concat(stderrChunks).toString('utf-8'),
      });
    });
  });
}

function buildArgs(opts: RunArgusOptions & { outDir: string }): string[] {
  const args = ['-m', 'argus.cli', 'scan', '--out', opts.outDir, '--quiet'];
  if (opts.inCluster !== false) args.push('--in-cluster');
  if (opts.kubeconfig) args.push('--kubeconfig', opts.kubeconfig);
  if (opts.context) args.push('--context', opts.context);
  if (opts.acceptedRisksDir) args.push('--accepted-risks', opts.acceptedRisksDir);
  if (opts.noNetwork) args.push('--no-network');
  if (opts.imagesOnly) args.push('--images-only');
  if (opts.clusterName) args.push('--cluster-name', opts.clusterName);
  return args;
}

/**
 * Find the directory that contains the `argus/` Python package. Walks up from
 * this source file (or its compiled `dist/` twin) until it finds a sibling
 * `argus` dir. Override with the `ARGUS_CWD` env var if you need something
 * else (the smoke script does that).
 */
async function resolveArgusCwd(): Promise<string> {
  const fromEnv = process.env.ARGUS_CWD;
  if (fromEnv && (await exists(join(fromEnv, 'argus', 'cli.py')))) return fromEnv;
  let cur = dirname(fileURLToPath(import.meta.url));
  for (let depth = 0; depth < 8; depth += 1) {
    if (await exists(join(cur, 'argus', 'cli.py'))) return cur;
    const parent = resolve(cur, '..');
    if (parent === cur) break;
    cur = parent;
  }
  throw new ArgusSpawnError(
    "couldn't locate the 'argus/' Python package (set ARGUS_CWD to its parent dir)",
  );
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path, fs.constants?.R_OK ?? 4);
    return true;
  } catch {
    return false;
  }
}

// --- Mapping: v3 ARGUS report → wire PostureSnapshot -----------------------

/** SSVC decision → wire severity. Higher tier == redder UI. */
const SSVC_TO_SEVERITY: Record<string, Severity> = {
  Act: 'critical',
  Attend: 'high',
  Track: 'medium',
  'Track*': 'low',
};

function mapFinding(
  f: ArgusScoredFinding,
  rawById: Map<string, ArgusActiveFinding>,
  workloadById: Map<string, ArgusWorkload>,
): WireFinding {
  const raw = rawById.get(f.id);
  const wl = workloadById.get(f.target);
  const [namespace, name] = splitTarget(f.target);
  return {
    id: cap(f.id, 256) || 'unknown',
    source: cap(raw?.source ?? 'argus', 256),
    ruleId: cap(f.cve ?? raw?.ruleId ?? raw?.cve ?? 'argus', 256),
    title: cap(f.title ?? raw?.title ?? f.cve ?? 'finding', 4096),
    severity: SSVC_TO_SEVERITY[f.decision] ?? mapRawSeverity(raw?.severity) ?? 'medium',
    resource: {
      kind: cap(wl?.kind ?? (f.target === 'cluster' ? 'Cluster' : 'Workload'), 256),
      name: cap(name || f.target, 256),
      namespace: namespace ? cap(namespace, 256) : undefined,
      image: wl?.image ? cap(wl.image, 512) : undefined,
    },
    reachable: f.confidence !== 'n/a',
    exploitScore: numberOrUndefined(f.score),
    baseScore: numberOrUndefined(f.cvss),
    // v3 emits descriptive control intel (KEV/ransomware/EPSS/SSVC) per
    // finding — Fase 3 will add a typed field. For now we stash it into the
    // generic `description` so it's reachable hosted-side without a schema
    // change.
    description: cap(describeFindingMetadata(f, raw), 16384),
  };
}

function mapRawSeverity(raw: string | undefined): Severity | undefined {
  if (!raw) return undefined;
  const norm = raw.toLowerCase();
  if (norm === 'critical' || norm === 'high' || norm === 'medium' || norm === 'low' || norm === 'info') {
    return norm as Severity;
  }
  return undefined;
}

function describeFindingMetadata(f: ArgusScoredFinding, raw: ArgusActiveFinding | undefined): string {
  const parts: string[] = [];
  if (f.cve) parts.push(`CVE: ${f.cve}`);
  if (f.kev) parts.push('KEV: yes');
  if (f.ransomware) parts.push('Ransomware: yes');
  if (typeof f.epss === 'number') parts.push(`EPSS: ${f.epss.toFixed(2)}`);
  if (f.decision) parts.push(`SSVC: ${f.decision}`);
  if (f.exposure) parts.push(`Exposure: ${f.exposure}`);
  if (f.confidence) parts.push(`Confidence: ${f.confidence}`);
  if (Array.isArray(f.reaches) && f.reaches.length) parts.push(`Reaches: ${f.reaches.join(',')}`);
  if (raw?.title && raw.title !== f.title) parts.push(`Scanner title: ${raw.title}`);
  return parts.join(' · ');
}

function mapPaths(
  paths: Record<string, ArgusPathStep[] | null>,
  workloadById: Map<string, ArgusWorkload>,
): WireAttackPath[] {
  return Object.entries(paths)
    .filter(([, steps]) => Array.isArray(steps) && steps.length > 0)
    .map(([jewel, steps], idx) => mapPath(idx, jewel, steps ?? [], workloadById));
}

function mapPath(
  idx: number,
  jewel: string,
  steps: ArgusPathStep[],
  workloadById: Map<string, ArgusWorkload>,
): WireAttackPath {
  const wireSteps: WireAttackStep[] = steps.map((s) => {
    const [, to, label, , inferred] = s;
    const target = stripPrefix(to);
    const wl = workloadById.get(target);
    return {
      kind: classifyNode(to),
      resource: {
        kind: wl?.kind ?? classifyResourceKind(to),
        name: cap(target.split('/').slice(-1)[0] ?? target, 256),
        namespace: extractNamespace(to),
        image: wl?.image ? cap(wl.image, 512) : undefined,
      },
      detail: cap(inferred ? `${label} (inferred)` : label, 4096),
      findingIds: [],
    };
  });
  return {
    id: `ap-${idx + 1}`,
    narrative: cap(narrativeFor(jewel, wireSteps), 16384),
    // Each crown-jewel path is "live and reachable" by definition (the engine
    // only emits paths that traverse from ext:internet to a jewel). Score it
    // 100 so it sorts above non-correlated findings in any UI sort-by-score.
    score: 100,
    entryPoint: 'internet',
    steps: wireSteps,
    findingIds: [],
  };
}

function narrativeFor(jewel: string, steps: WireAttackStep[]): string {
  const target = prettyNode(jewel);
  if (steps.length === 0) return `External attacker can reach ${target}.`;
  const chain = steps
    .slice(0, 6)
    .map((s) => `${s.resource.kind} ${s.resource.namespace ? `${s.resource.namespace}/` : ''}${s.resource.name}`)
    .join(' → ');
  return `Internet → ${chain} → ${target}`;
}

function mapChokePoints(
  chokes: ArgusChokePoint[],
  reachableJewels: string[],
): WireRemediation[] {
  return chokes.map((ch, i) => {
    const ctrl = ch.control ?? {};
    const total = reachableJewels.length || 1;
    return {
      id: `cp-${i + 1}`,
      playbookId: cap(ctrl.type ?? 'unknown', 256),
      title: cap(describeControl(ctrl), 4096),
      severity: severityForBreaks(ch.breaks, total),
      kind: 'manual',
      rationale: cap(
        `Eliminates ${ch.breaks} of ${total} active attack paths` +
          (ch.targets?.length ? ` to ${ch.targets.map(prettyNode).join(', ')}` : ''),
        16384,
      ),
      path: '',
      diff: '',
      manualSteps: [cap(describeControl(ctrl), 4096)],
      controls: [],
      findingIds: [],
      // ARGUS chokepoints aren't tied to a single attack-path id; omit.
      attackPathId: undefined,
      // Higher breaks → higher priority. Wire priority is just a number;
      // hosted side sorts on it.
      priority: ch.breaks,
      branch: '',
      prTitle: cap(describeControl(ctrl), 4096),
      prBody: cap(
        `Choke-point fix surfaced by ARGUS v3. Apply this and ${ch.breaks} of ` +
          `${total} active attack paths collapse.`,
        16384,
      ),
    };
  });
}

function severityForBreaks(breaks: number, total: number): Severity {
  if (total > 0 && breaks >= total) return 'critical';
  if (breaks >= Math.max(2, Math.ceil(total / 2))) return 'high';
  if (breaks > 0) return 'medium';
  return 'low';
}

function buildRunRecord(report: ArgusReportJson): WireRun {
  const intel = report.intel ?? { kev_count: 0, version: '?', source: 'override-only' };
  const startedAt = (report.scannedAt as string | undefined) ?? new Date().toISOString();
  const summary =
    `ARGUS v3 · CISA KEV ${intel.source ?? 'override'} (${intel.version ?? '?'}) · ` +
    `${intel.kev_count ?? 0} known-exploited · ` +
    `${report.reachableJewels?.length ?? 0} crown-jewel target(s) reachable`;
  return {
    id: `argus-${Date.parse(startedAt) || Date.now()}`,
    status: 'complete',
    engine: 'argus-v3',
    usedFixtures: false,
    findingCount: report.findings?.length ?? 0,
    pathCount: Object.values(report.paths ?? {}).filter((s) => Array.isArray(s) && s.length).length,
    riskScore: typeof report.riskScore === 'number' ? report.riskScore : null,
    summary: cap(summary, 16384),
    startedAt: cap(startedAt, 64),
    finishedAt: cap(new Date().toISOString(), 64),
  };
}

// --- Small helpers ----------------------------------------------------------

function splitTarget(target: string): [string, string] {
  const idx = target.indexOf('/');
  if (idx < 0) return ['', target];
  return [target.slice(0, idx), target.slice(idx + 1)];
}

function classifyNode(id: string): string {
  if (id.startsWith('wl:')) return 'workload';
  if (id.startsWith('sa:')) return 'service-account';
  if (id.startsWith('secret:')) return 'secret';
  if (id.startsWith('node:')) return 'node';
  if (id.startsWith('crole:')) return 'cloud-role';
  if (id.startsWith('clouddata:')) return 'cloud-data';
  if (id === 'CLUSTER-ADMIN') return 'cluster-admin';
  if (id === 'CLOUD-ADMIN') return 'cloud-admin';
  return 'unknown';
}

function classifyResourceKind(id: string): string {
  if (id.startsWith('wl:')) return 'Workload';
  if (id.startsWith('sa:')) return 'ServiceAccount';
  if (id.startsWith('secret:')) return 'Secret';
  if (id.startsWith('node:')) return 'Node';
  if (id.startsWith('crole:')) return 'CloudRole';
  if (id.startsWith('clouddata:')) return 'CloudResource';
  return 'JewelNode';
}

function stripPrefix(id: string): string {
  const c = id.indexOf(':');
  return c >= 0 ? id.slice(c + 1) : id;
}

function extractNamespace(id: string): string | undefined {
  const target = stripPrefix(id);
  const idx = target.indexOf('/');
  if (idx <= 0) return undefined;
  return cap(target.slice(0, idx), 256);
}

function prettyNode(id: string): string {
  if (id === 'CLUSTER-ADMIN') return 'cluster-admin';
  if (id === 'CLOUD-ADMIN') return 'cloud-admin';
  if (id.startsWith('secret:')) return `Secret ${stripPrefix(id)}`;
  if (id.startsWith('wl:')) return stripPrefix(id);
  if (id.startsWith('sa:')) return `SA ${stripPrefix(id)}`;
  if (id.startsWith('clouddata:')) return `CloudData ${stripPrefix(id)}`;
  if (id.startsWith('crole:')) return `CloudRole ${stripPrefix(id)}`;
  if (id.startsWith('node:')) return `Node ${stripPrefix(id)}`;
  return id;
}

function describeControl(ctrl: ArgusControl): string {
  switch (ctrl.type) {
    case 'patch':
      return `Patch ${ctrl.ref ?? '?'} on ${ctrl.workload ?? '?'}`;
    case 'rbac-least-privilege':
      return `Remove ${ctrl.what ?? '?'} RBAC from ${ctrl.sa ?? '?'}`;
    case 'harden-securitycontext':
      return `Drop privileged/hostPath on ${ctrl.workload ?? '?'}`;
    case 'scope-cloud-identity':
      return `Scope or remove cloud identity on ${ctrl.sa ?? '?'}`;
    case 'restrict-assume-role':
      return `Restrict sts:AssumeRole on ${ctrl.role ?? '?'}`;
    case 'network-isolate':
      return `Add NetworkPolicy isolating ${ctrl.workload ?? '?'}`;
    default:
      return ctrl.type ?? 'unknown fix';
  }
}

function cap(s: unknown, max: number): string {
  if (s === undefined || s === null) return '';
  const text = typeof s === 'string' ? s : String(s);
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function numberOrUndefined(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

// --- Errors ----------------------------------------------------------------

export class ArgusSpawnError extends Error {
  constructor(message: string) {
    super(`argus spawn failed: ${message}`);
    this.name = 'ArgusSpawnError';
  }
}

export class ArgusExitError extends Error {
  constructor(
    readonly code: number | null,
    readonly signal: NodeJS.Signals | null,
    readonly stderr: string,
  ) {
    super(`argus exited with code=${code} signal=${signal}; stderr=${stderr.slice(-1024)}`);
    this.name = 'ArgusExitError';
  }
}

export class ArgusOutputError extends Error {
  constructor(message: string) {
    super(`argus output invalid: ${message}`);
    this.name = 'ArgusOutputError';
  }
}

// --- Types: the v3 JSON shape we read from `report.json` -------------------

export interface ArgusReportJson {
  cluster?: string;
  scannedAt?: string;
  riskScore?: number;
  intel?: { kev_count?: number; version?: string; source?: string };
  reachableJewels?: string[];
  paths?: Record<string, ArgusPathStep[] | null>;
  chokePoints?: ArgusChokePoint[];
  findings?: ArgusScoredFinding[];
  acceptedRisks?: unknown[];
  refusals?: unknown[];
  autoReopened?: unknown[];
  workloads?: ArgusWorkload[];
  activeFindings?: ArgusActiveFinding[];
  metadata?: { scanners?: unknown[]; threat_intel?: unknown };
}

export interface ArgusScoredFinding {
  id: string;
  cve?: string;
  title: string;
  target: string;
  kev?: boolean;
  ransomware?: boolean;
  epss?: number;
  cvss?: number;
  exposure?: string;
  confidence?: string;
  decision: 'Act' | 'Attend' | 'Track' | 'Track*';
  score: number;
  reaches?: string[];
}

export interface ArgusActiveFinding {
  id: string;
  source?: string;
  type?: string;
  cve?: string;
  ruleId?: string;
  severity?: string;
  target?: string;
  title?: string;
}

export interface ArgusWorkload {
  id: string;
  kind?: string;
  namespace: string;
  image: string;
}

export interface ArgusChokePoint {
  control: ArgusControl;
  breaks: number;
  targets?: string[];
}

export interface ArgusControl {
  type?: string;
  ref?: string;
  workload?: string;
  sa?: string;
  what?: string;
  role?: string;
}

/** v3 paths entries: [from, to, label, control, inferred] */
export type ArgusPathStep = [
  from: string,
  to: string,
  label: string,
  control: ArgusControl | null,
  inferred: boolean,
];
