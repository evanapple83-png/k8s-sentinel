#!/usr/bin/env node
/**
 * sentinel — K8s Sentinel CLI.
 *
 *   sentinel scan [--namespace ns] [--kubeconfig path] [--image img ...]
 *   sentinel runs
 *   sentinel findings <runId>
 *   sentinel paths [runId]
 *   sentinel ask "<plain-English query>" [--run <runId>]
 *
 * Runs read-only. Falls back to offline fixtures when no cluster/scanners are
 * present, so it always produces a result.
 */
import { silenceExperimentalWarnings } from './util/warnings.js';
import { loadConfig } from './config.js';
import { runScan } from './orchestrator.js';
import { SqliteStore } from './store.js';
import { analyzeReachability, answerQuery } from '@k8s-sentinel/agent-analyst';
import type { Severity } from '@k8s-sentinel/core';

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
    default:
      printUsage();
      process.exitCode = command ? 1 : 0;
  }
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

Examples:
  sentinel ask "show everything internet-exposed running as root"
  sentinel ask "critical findings in prod"
  sentinel paths`);
}

main().catch((err) => {
  console.error('sentinel: error —', err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
