#!/usr/bin/env node
/**
 * sentinel — K8s Sentinel CLI.
 *
 *   sentinel scan [--namespace ns] [--kubeconfig path] [--image img ...]
 *   sentinel runs
 *   sentinel findings <runId>
 *   sentinel paths [runId]
 *   sentinel ask "<plain-English query>" [--run <runId>]
 *   sentinel report [runId] [--format md|json|html|pdf] [--out <file>]
 *   sentinel fixes [runId]
 *   sentinel approve <fixId> [--run <runId>]
 *   sentinel audit [--run <runId>] [--verify]
 *   sentinel serve
 *   sentinel agent            (hybrid mode: dial the relay, serve commands)
 *
 * Runs read-only. Falls back to offline fixtures when no cluster/scanners are
 * present, so it always produces a result.
 */
import { writeFileSync } from 'node:fs';
import { silenceExperimentalWarnings } from './util/warnings.js';
import { loadConfig } from './config.js';
import { runScan } from './orchestrator.js';
import { SqliteStore } from './store.js';
import { createServer } from './server.js';
import {
  approveFix,
  approvedFixIds,
  auditSink,
  loadRun,
  proposalsForRun,
  renderReport,
  reportForRun,
  type ReportFormat,
} from './reporting.js';
import { analyzeReachability, answerQuery } from '@k8s-sentinel/agent-analyst';
import type { Severity } from '@k8s-sentinel/core';
import { runAgent } from './tunnel/agent.js';

silenceExperimentalWarnings();

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const COLOR: Record<Severity, string> = {
  critical: '\x1b[41m\x1b[97m',
  high: '\x1b[31m',
  medium: '\x1b[33m',
  low: '\x1b[36m',
  info: '\x1b[90m',
};
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;
  switch (command) {
    case 'scan':
      return cmdScan(rest);
    case 'runs':
      return cmdRuns();
    case 'findings':
      return cmdFindings(rest[0]);
    case 'paths':
      return cmdPaths(rest[0]);
    case 'ask':
      return cmdAsk(rest);
    case 'report':
      return cmdReport(rest);
    case 'fixes':
      return cmdFixes(rest[0]);
    case 'approve':
      return cmdApprove(rest);
    case 'audit':
      return cmdAudit(rest);
    case 'serve':
      return cmdServe();
    case 'agent':
      return runAgent();
    default:
      printUsage();
      process.exitCode = command ? 1 : 0;
  }
}

async function cmdReport(args: string[]): Promise<void> {
  let format: ReportFormat = 'md';
  let out: string | undefined;
  let runId: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--format' || a === '-f') format = args[++i] as ReportFormat;
    else if (a === '--out' || a === '-o') out = args[++i];
    else if (!a.startsWith('-')) runId ??= a;
  }

  const store = new SqliteStore(loadConfig().dbPath);
  const id = runId ?? store.listRuns(1)[0]?.id;
  if (!id) {
    console.log('No runs yet. Try: sentinel scan');
    store.close();
    return;
  }
  const bundle = loadRun(store, id);
  store.close();
  if (!bundle) {
    console.error(`sentinel: run ${id} not found`);
    process.exitCode = 1;
    return;
  }

  const { body, ext } = renderReport(reportForRun(bundle), format);
  if (out) {
    writeFileSync(out, typeof body === 'string' ? body : Buffer.from(body));
    console.log(`✓ wrote ${ext.toUpperCase()} report → ${out}`);
    return;
  }
  if (typeof body !== 'string') {
    console.error('sentinel: pdf is binary — pass --out <file.pdf>');
    process.exitCode = 1;
    return;
  }
  process.stdout.write(body);
}

async function cmdFixes(runId?: string): Promise<void> {
  const store = new SqliteStore(loadConfig().dbPath);
  const id = runId ?? store.listRuns(1)[0]?.id;
  if (!id) {
    console.log('No runs yet. Try: sentinel scan');
    store.close();
    return;
  }
  const bundle = loadRun(store, id);
  store.close();
  if (!bundle) {
    console.error(`sentinel: run ${id} not found`);
    process.exitCode = 1;
    return;
  }

  const proposals = proposalsForRun(bundle);
  const approved = await approvedFixIds(id);
  console.log(`${BOLD}Remediations${RESET} ${DIM}(run ${id}, propose-only — nothing is applied)${RESET}`);
  if (proposals.length === 0) console.log('  (none proposed)');
  for (const p of proposals) {
    const mark = approved.has(p.id) ? `${COLOR.low} approved ${RESET}` : `${DIM}proposed${RESET}`;
    console.log(
      `  ${DIM}${p.id}${RESET}  ${COLOR[p.severity]}${p.severity.toUpperCase().padEnd(8)}${RESET} ${p.title}  ${mark}`,
    );
    console.log(`     ${DIM}${p.kind} · ${p.path} · fixes ${p.findingIds.length} finding(s)${RESET}`);
  }
  console.log(`\n${DIM}approve one with: sentinel approve <fixId> --run ${id}${RESET}`);
}

async function cmdApprove(args: string[]): Promise<void> {
  const runIdx = args.findIndex((a) => a === '--run');
  const runId = runIdx >= 0 ? args[runIdx + 1] : undefined;
  const fixId = args.find(
    (a, i) => !a.startsWith('-') && (runIdx < 0 || (i !== runIdx && i !== runIdx + 1)),
  );
  if (!fixId) {
    console.error('usage: sentinel approve <fixId> [--run <runId>]');
    process.exitCode = 1;
    return;
  }

  const store = new SqliteStore(loadConfig().dbPath);
  const id = runId ?? store.listRuns(1)[0]?.id;
  if (!id) {
    console.log('No runs yet. Try: sentinel scan');
    store.close();
    return;
  }
  const result = await approveFix({ store, runId: id, fixId, actor: 'user' });
  store.close();
  if (!result) {
    console.error(`sentinel: fix ${fixId} not found in run ${id}`);
    process.exitCode = 1;
    return;
  }
  console.log(`${BOLD}✓ Approved${RESET} ${result.proposalId}`);
  console.log(`  branch:  ${result.bundle.branch}`);
  console.log(
    `  bundle:  ${result.dir}/PR.md${result.bundle.files.length ? '  (+ changes.patch)' : ''}`,
  );
  console.log(`  ${DIM}Reviewable PR bundle written. Nothing was applied to your cluster.${RESET}`);
}

async function cmdAudit(args: string[]): Promise<void> {
  const runIdx = args.findIndex((a) => a === '--run');
  const runId = runIdx >= 0 ? args[runIdx + 1] : undefined;
  const sink = auditSink();
  const entries = await sink.list(runId);
  console.log(`${BOLD}Audit trail${RESET}${runId ? ` ${DIM}(run ${runId})${RESET}` : ''}`);
  for (const e of entries) {
    const who = e.agent ? `${e.actor}:${e.agent}` : e.actor;
    console.log(`  ${DIM}#${String(e.seq).padStart(3)} ${e.ts}${RESET}  ${who.padEnd(20)} ${e.action}`);
  }
  if (args.includes('--verify')) {
    const v = await sink.verify();
    console.log(
      `\n${v.ok ? `${COLOR.low} chain intact ${RESET}` : `${COLOR.critical} BROKEN at #${v.brokenAt} ${RESET}`}`,
    );
  }
  console.log(`\n${entries.length} entries.`);
}

function cmdServe(): void {
  const config = loadConfig();
  const server = createServer(config);
  server.listen(config.apiPort, () => {
    console.log(
      `${BOLD}K8s Sentinel API${RESET} on http://localhost:${config.apiPort} ${DIM}(engine: ${config.engine})${RESET}`,
    );
    console.log(`${DIM}GET /api/scan/stream · /api/runs/:id · /:id/report?format=pdf · POST /api/fixes/:id/approve${RESET}`);
  });
}

async function cmdScan(args: string[]): Promise<void> {
  const flags = parseFlags(args);
  const config = loadConfig();
  console.log(`${BOLD}K8s Sentinel${RESET} — scan starting (engine: ${config.engine})\n`);

  const start = Date.now();
  const { run, findings, paths } = await runScan({
    config,
    target: {
      namespace: flags.namespace,
      kubeconfig: flags.kubeconfig,
      images: flags.image,
    },
    onProgress: (m) => console.log(`${DIM}· ${m}${RESET}`),
  });

  console.log(`\n${BOLD}Posture${RESET}  (run ${run.id}, ${Date.now() - start}ms)`);
  console.log(`  ${riskBadge(run.riskScore)}  ${DIM}${run.summary ?? ''}${RESET}`);

  const counts = countBySeverity(findings);
  console.log(`\n${BOLD}Findings${RESET}`);
  for (const sev of SEV_ORDER) {
    const n = counts[sev] ?? 0;
    if (n === 0) continue;
    console.log(`  ${COLOR[sev]} ${sev.toUpperCase().padEnd(8)} ${RESET} ${n}`);
  }

  // Ranked by exploitability (reachability-weighted), not raw CVSS.
  const top = [...findings].sort((a, b) => (b.exploitScore ?? 0) - (a.exploitScore ?? 0)).slice(0, 8);
  console.log(`\n${BOLD}Top findings${RESET} ${DIM}(by exploitability)${RESET}`);
  for (const f of top) {
    const where = f.resource.namespace ? `${f.resource.namespace}/` : '';
    const reach = f.reachable ? `${COLOR.critical} REACHABLE ${RESET} ` : '';
    console.log(
      `  ${DIM}${String(f.exploitScore ?? 0).padStart(3)}${RESET} ` +
        `${COLOR[f.severity]}${f.severity[0]!.toUpperCase()}${RESET} ${reach}` +
        `${DIM}[${f.source}]${RESET} ${f.title} ${DIM}— ${where}${f.resource.name}${RESET}`,
    );
  }

  if (paths.length > 0) {
    console.log(`\n${BOLD}Attack paths${RESET} ${DIM}(correlated, ranked)${RESET}`);
    for (const p of paths.slice(0, 5)) printPath(p);
  }

  console.log(
    `\n${run.usedFixtures ? '⚠ used offline fixtures (no live cluster/scanners detected)\n' : ''}` +
      `✓ ${findings.length} findings + ${paths.length} attack path(s) persisted.`,
  );
}

async function cmdPaths(runId?: string): Promise<void> {
  const store = new SqliteStore(loadConfig().dbPath);
  const id = runId ?? store.listRuns(1)[0]?.id;
  if (!id) {
    console.log('No runs yet. Try: sentinel scan');
    store.close();
    return;
  }
  const paths = store.getAttackPaths(id);
  console.log(`${BOLD}Attack paths${RESET} ${DIM}(run ${id})${RESET}`);
  if (paths.length === 0) console.log('  (none — nothing both reachable and exploitable)');
  for (const p of paths) printPath(p, true);
  store.close();
}

async function cmdAsk(args: string[]): Promise<void> {
  const runFlagIdx = args.findIndex((a) => a === '--run');
  const runId = runFlagIdx >= 0 ? args[runFlagIdx + 1] : undefined;
  const query = args
    .filter((_, i) => runFlagIdx < 0 || (i !== runFlagIdx && i !== runFlagIdx + 1))
    .join(' ')
    .trim();
  if (!query) {
    console.error('usage: sentinel ask "<plain-English query>" [--run <runId>]');
    process.exitCode = 1;
    return;
  }

  const store = new SqliteStore(loadConfig().dbPath);
  const id = runId ?? store.listRuns(1)[0]?.id;
  const inventory = id ? store.getInventory(id) : undefined;
  if (!id || !inventory) {
    console.log('No analysed run found. Try: sentinel scan');
    store.close();
    return;
  }

  // Rebuild the per-finding context deterministically from the stored snapshot.
  const stored = store.getFindings(id);
  const { contexts } = analyzeReachability(stored, inventory);
  const res = answerQuery(query, {
    findings: stored,
    paths: store.getAttackPaths(id),
    contexts,
    namespaces: inventory.namespaces,
  });

  console.log(`${DIM}? ${query}${RESET}`);
  console.log(`${BOLD}${res.answer}${RESET}\n`);
  for (const f of res.findings.slice(0, 12)) {
    const where = f.resource.namespace ? `${f.resource.namespace}/` : '';
    console.log(
      `  ${DIM}${String(f.exploitScore ?? 0).padStart(3)}${RESET} ` +
        `${COLOR[f.severity]}${f.severity[0]!.toUpperCase()}${RESET} ` +
        `${DIM}[${f.source}]${RESET} ${f.title} ${DIM}— ${where}${f.resource.name}${RESET}`,
    );
  }
  if (res.parsed.unmatched) {
    console.log(`\n${DIM}note: couldn't interpret "${res.parsed.unmatched}" — showing best match.${RESET}`);
  }
  store.close();
}

function printPath(p: { score: number; entryPoint?: string; narrative: string; steps: { kind: string }[] }, verbose = false): void {
  console.log(`  ${riskBadge(p.score)}  ${DIM}${p.entryPoint ?? 'in-cluster'} →${RESET} ${p.narrative}`);
  if (verbose) console.log(`       ${DIM}${p.steps.map((s) => s.kind).join(' → ')}${RESET}`);
}

/** Color-coded 0–100 risk badge: green < 40, amber < 70, red ≥ 70. */
function riskBadge(score: number | null): string {
  const s = score ?? 0;
  const color = s >= 70 ? COLOR.critical : s >= 40 ? COLOR.medium : '\x1b[42m\x1b[97m';
  return `${color} risk ${String(s).padStart(3)}/100 ${RESET}`;
}

async function cmdRuns(): Promise<void> {
  const store = new SqliteStore(loadConfig().dbPath);
  const runs = store.listRuns();
  if (runs.length === 0) {
    console.log('No runs yet. Try: sentinel scan');
    return;
  }
  console.log(`${BOLD}Recent runs${RESET}`);
  for (const r of runs) {
    console.log(
      `  ${r.id}  ${DIM}${r.createdAt}${RESET}  ${r.status}  ` +
        `${r.findingCount} findings${r.usedFixtures ? ' (fixtures)' : ''}`,
    );
  }
  store.close();
}

async function cmdFindings(runId?: string): Promise<void> {
  if (!runId) {
    console.error('usage: sentinel findings <runId>');
    process.exitCode = 1;
    return;
  }
  const store = new SqliteStore(loadConfig().dbPath);
  const findings = store.getFindings(runId);
  for (const f of findings) {
    console.log(`${COLOR[f.severity]}${f.severity.toUpperCase().padEnd(8)}${RESET} [${f.source}] ${f.ruleId}  ${f.title}`);
  }
  console.log(`\n${findings.length} findings.`);
  store.close();
}

function countBySeverity(findings: { severity: Severity }[]): Partial<Record<Severity, number>> {
  const out: Partial<Record<Severity, number>> = {};
  for (const f of findings) out[f.severity] = (out[f.severity] ?? 0) + 1;
  return out;
}

interface Flags {
  namespace?: string;
  kubeconfig?: string;
  image?: string[];
}
function parseFlags(args: string[]): Flags {
  const flags: Flags = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--namespace' || a === '-n') flags.namespace = args[++i];
    else if (a === '--kubeconfig') flags.kubeconfig = args[++i];
    else if (a === '--image') (flags.image ??= []).push(args[++i]!);
  }
  return flags;
}

function printUsage(): void {
  console.log(`K8s Sentinel CLI

Usage:
  sentinel scan [--namespace <ns>] [--kubeconfig <path>] [--image <img>]
  sentinel runs
  sentinel findings <runId>
  sentinel paths [runId]
  sentinel ask "<plain-English query>" [--run <runId>]
  sentinel report [runId] [--format md|json|html|pdf] [--out <file>]
  sentinel fixes [runId]
  sentinel approve <fixId> [--run <runId>]
  sentinel audit [--run <runId>] [--verify]
  sentinel serve
  sentinel agent                       (hybrid mode: dial RELAY_URL, serve commands)

Examples:
  sentinel ask "show everything internet-exposed running as root"
  sentinel report --format pdf --out report.pdf
  sentinel fixes
  sentinel approve fix:1a2b3c4d
  sentinel audit --verify`);
}

main().catch((err) => {
  console.error('sentinel: error —', err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
