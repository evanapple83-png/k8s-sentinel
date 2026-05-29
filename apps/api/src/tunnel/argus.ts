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
 * Wire mapping (Fase 3 — typed v3 fields land first-class):
 *   - KEV / ransomware / EPSS / CVE / SSVC / exposure / confidence / reaches
 *     → typed WireFinding fields (no more description-smuggling).
 *   - SSVC decision still drives WireFinding.severity so the legacy UI keeps
 *     its colour; the typed `ssvc` field lets the v3-aware dashboard render
 *     "Act / Attend / Track" badges directly.
 *   - choke-points  → typed `snapshot.chokePoints` (the v3 panel). Same
 *     entries ALSO go into `remediations` so the existing Fixes screen still
 *     works without a schema migration to the legacy UI.
 *   - threat-intel  → typed `snapshot.intel` (banner). The run.summary still
 *     carries a human-readable one-liner for non-v3 viewers.
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
  type WireChokePoint,
  type WireFinding,
  type WireRemediation,
  type WireRun,
  type WireThreatIntel,
  type Severity,
  type SsvcDecision,
  type Confidence,
  type Exposure,
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

  // report.findings is the engine's CVE-correlated/scored set; non-CVE scanner
  // findings (kube-bench CIS, kubescape misconfig) live only in activeFindings
  // and would otherwise be dropped from the dashboard. Surface them too. (F15)
  const scoredIds = new Set((report.findings ?? []).map((f) => f.id));
  const findings = [
    ...(report.findings ?? []).map((f) => mapFinding(f, rawById, workloadById)),
    ...(report.activeFindings ?? [])
      .filter((r) => !scoredIds.has(r.id) && (r.type ?? '') !== 'cve')
      .map((r) => mapRawFinding(r, workloadById)),
  ];
  const paths = mapPaths(report.paths ?? {}, workloadById);
  const chokePoints = mapChokePointsTyped(report.chokePoints ?? [], report.reachableJewels ?? []);
  const remediations = mapChokePointsToRemediations(chokePoints);
  // findingCount must reflect ALL findings (incl. the non-CVE kube-bench/
  // kubescape ones surfaced above), not just the engine's CVE-correlated set. (F17)
  const run = { ...buildRunRecord(report), findingCount: findings.length };
  const intel = mapIntel(report.intel);

  const snap: PostureSnapshot = { run, findings, paths, remediations, audit: [] };
  if (intel) snap.intel = intel;
  if (chokePoints.length) snap.chokePoints = chokePoints;
  return snap;
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
  const wf: WireFinding = {
    id: cap(f.id, 256) || 'unknown',
    source: cap(raw?.source ?? 'argus', 256),
    ruleId: cap(f.cve ?? raw?.ruleId ?? raw?.cve ?? 'argus', 256),
    title: cap(f.title ?? raw?.title ?? f.cve ?? 'finding', 4096),
    // SSVC drives wire severity (so legacy UI keeps its colour); the typed
    // `ssvc` field below lets the v3-aware UI render the raw decision.
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
    // Keep the scanner's own description text in `description` when it
    // differs from the title; the v3 metadata used to be smuggled here but
    // now lives in typed fields below.
    description:
      raw?.title && raw.title !== f.title ? cap(raw.title, 16384) : undefined,
    // --- typed v3 fields ----------------------------------------------------
    cve: f.cve ? cap(f.cve, 64) : undefined,
    kev: typeof f.kev === 'boolean' ? f.kev : undefined,
    ransomware: typeof f.ransomware === 'boolean' ? f.ransomware : undefined,
    epss: typeof f.epss === 'number' && Number.isFinite(f.epss) ? clamp01(f.epss) : undefined,
    ssvc: isSsvc(f.decision) ? (f.decision as SsvcDecision) : undefined,
    confidence: isConfidence(f.confidence) ? (f.confidence as Confidence) : undefined,
    exposure: isExposure(f.exposure) ? (f.exposure as Exposure) : undefined,
    reaches: Array.isArray(f.reaches) && f.reaches.length ? f.reaches.slice(0, 32).map((r) => cap(r, 64)) : undefined,
  };
  // Strip undefined keys so the wire frame stays small. (Zod tolerates them
  // but JSON.stringify writes `null` for explicit undefined in objects? no —
  // strips them. This block is for clarity, not correctness.)
  for (const k of Object.keys(wf) as (keyof WireFinding)[]) {
    if (wf[k] === undefined) delete (wf as Record<string, unknown>)[k];
  }
  return wf;
}

/**
 * Map a raw (non-CVE) scanner finding — kube-bench CIS / kubescape misconfig —
 * straight to a wire finding. These never get the engine's CVE correlation, so
 * severity comes from the scanner itself and reachable is false. (F15)
 */
function mapRawFinding(raw: ArgusActiveFinding, workloadById: Map<string, ArgusWorkload>): WireFinding {
  const target = raw.target ?? 'cluster';
  const wl = workloadById.get(target);
  const [namespace, name] = splitTarget(target);
  const wf: WireFinding = {
    id: cap(raw.id, 256) || 'unknown',
    source: cap(raw.source ?? 'argus', 256),
    ruleId: cap(raw.ruleId ?? raw.cve ?? 'argus', 256),
    title: cap(raw.title ?? raw.ruleId ?? 'finding', 4096),
    severity: mapRawSeverity(raw.severity) ?? 'medium',
    resource: {
      kind: cap(wl?.kind ?? (target === 'cluster' ? 'Cluster' : 'Workload'), 256),
      name: cap(name || target, 256),
      namespace: namespace ? cap(namespace, 256) : undefined,
      image: wl?.image ? cap(wl.image, 512) : undefined,
    },
    reachable: false,
  };
  for (const k of Object.keys(wf) as (keyof WireFinding)[]) {
    if (wf[k] === undefined) delete (wf as Record<string, unknown>)[k];
  }
  return wf;
}

function clamp01(n: number): number {
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

function isSsvc(v: unknown): v is SsvcDecision {
  return v === 'Act' || v === 'Attend' || v === 'Track' || v === 'Track*';
}

function isConfidence(v: unknown): v is Confidence {
  return v === 'high' || v === 'medium' || v === 'n/a';
}

function isExposure(v: unknown): v is Exposure {
  return v === 'open' || v === 'internal' || v === 'small' || v === 'cluster';
}

function mapRawSeverity(raw: string | undefined): Severity | undefined {
  if (!raw) return undefined;
  const norm = raw.toLowerCase();
  if (norm === 'critical' || norm === 'high' || norm === 'medium' || norm === 'low' || norm === 'info') {
    return norm as Severity;
  }
  return undefined;
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

/** Map ARGUS choke-points to the typed wire shape (the v3 source of truth). */
function mapChokePointsTyped(
  chokes: ArgusChokePoint[],
  reachableJewels: string[],
): WireChokePoint[] {
  const total = reachableJewels.length || 0;
  return chokes.map((ch, i) => {
    const ctrl = ch.control ?? {};
    return {
      id: `cp-${i + 1}`,
      control: {
        type: cap(ctrl.type ?? 'unknown', 64),
        ref: ctrl.ref ? cap(ctrl.ref, 128) : undefined,
        workload: ctrl.workload ? cap(ctrl.workload, 256) : undefined,
        sa: ctrl.sa ? cap(ctrl.sa, 256) : undefined,
        what: ctrl.what ? cap(ctrl.what, 128) : undefined,
        role: ctrl.role ? cap(ctrl.role, 256) : undefined,
      },
      breaks: Math.max(0, Math.trunc(ch.breaks ?? 0)),
      totalPaths: total,
      targets: Array.isArray(ch.targets) ? ch.targets.slice(0, 64).map((t) => cap(t, 256)) : [],
      severity: severityForBreaks(ch.breaks ?? 0, total || 1),
      description: cap(describeControl(ctrl), 4096),
      priority: ch.breaks ?? 0,
    };
  });
}

/**
 * Mirror the typed choke-points as legacy WireRemediation entries so the old
 * "Fixes" screen keeps rendering them while the v3 dashboard panel ramps up.
 * Once the dashboard reads `snapshot.chokePoints` exclusively this can be
 * dropped (and the wire frame shrinks).
 */
function mapChokePointsToRemediations(chokes: WireChokePoint[]): WireRemediation[] {
  return chokes.map((ch) => ({
    id: ch.id,
    playbookId: cap(ch.control.type, 256),
    title: cap(ch.description, 4096),
    severity: ch.severity,
    kind: 'manual',
    rationale: cap(
      `Eliminates ${ch.breaks} of ${ch.totalPaths || 1} active attack paths` +
        (ch.targets.length ? ` to ${ch.targets.map(prettyNode).join(', ')}` : ''),
      16384,
    ),
    path: '',
    diff: '',
    manualSteps: [ch.description],
    controls: [],
    findingIds: [],
    attackPathId: undefined,
    priority: ch.priority,
    branch: '',
    prTitle: cap(ch.description, 4096),
    prBody: cap(
      `Choke-point fix surfaced by ARGUS v3. Apply this and ${ch.breaks} of ` +
        `${ch.totalPaths || 1} active attack paths collapse.`,
      16384,
    ),
  }));
}

function mapIntel(intel: ArgusReportJson['intel']): WireThreatIntel | undefined {
  if (!intel) return undefined;
  const version = typeof intel.version === 'string' ? intel.version : '';
  const source = typeof intel.source === 'string' ? intel.source : '';
  // The catalog is essentially mandatory in v3; if neither field landed treat
  // it as "no intel" and omit from the snapshot rather than emit junk.
  if (!version && !source) return undefined;
  const out: WireThreatIntel = {
    source: cap(source || 'unknown', 64),
    version: cap(version || '?', 64),
    kevCount: Math.max(0, Math.trunc(intel.kev_count ?? 0)),
  };
  if (typeof intel.epss_count === 'number' && Number.isFinite(intel.epss_count)) {
    out.epssCount = Math.max(0, Math.trunc(intel.epss_count));
  }
  return out;
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
  const waived = Array.isArray(report.acceptedRisks) ? report.acceptedRisks.length : 0;
  const refused = Array.isArray(report.refusals) ? report.refusals.length : 0;
  const reopened = Array.isArray(report.autoReopened) ? report.autoReopened.length : 0;
  // Surface accepted-risk activity in the summary so every dashboard header
  // shows "N waived · M auto-reopened" without a schema migration. Fase 6
  // proper will lift this into typed snapshot.waivers + a dedicated UI panel.
  const waiverSuffix =
    waived || refused || reopened
      ? ` · ${waived} waived, ${refused} refused, ${reopened} auto-reopened`
      : '';
  const summary =
    `ARGUS v3 · CISA KEV ${intel.source ?? 'override'} (${intel.version ?? '?'}) · ` +
    `${intel.kev_count ?? 0} known-exploited · ` +
    `${report.reachableJewels?.length ?? 0} crown-jewel target(s) reachable` +
    waiverSuffix;
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
  intel?: { kev_count?: number; epss_count?: number; version?: string; source?: string };
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
