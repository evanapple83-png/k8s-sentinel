import { FileAuditSink, type AttackPath, type AuditSink, type Finding } from '@k8s-sentinel/core';
import { runCollector } from '@k8s-sentinel/agent-collector';
import { runAnalyst } from '@k8s-sentinel/agent-analyst';
import { proposeRemediations, type RemediationProposal } from '@k8s-sentinel/agent-author';
import type { ScanTarget } from '@k8s-sentinel/tools-mcp';
import { loadConfig, type SentinelConfig } from './config.js';
import { createEngine } from './engine.js';
import { SqliteStore, type RunRecord } from './store.js';

export interface ScanOptions {
  target?: ScanTarget;
  config?: SentinelConfig;
  store?: SqliteStore;
  audit?: AuditSink;
  onProgress?: (msg: string) => void;
}

export interface ScanResultSummary {
  run: RunRecord;
  findings: Finding[];
  paths: AttackPath[];
  proposals: RemediationProposal[];
}

/**
 * Orchestrates a full scan run: Collector (Phase 1) gathers + normalizes
 * findings, the Analyst (Phase 2) enriches them with reachability, correlates
 * ranked attack paths, and maps compliance controls, then the Author (Phase 3)
 * proposes reviewable remediations. Persists findings + inventory + paths and
 * writes the immutable audit trail. Holds no cluster write creds (BUILD.md §4);
 * remediations are proposals only — nothing is applied here.
 */
export async function runScan(opts: ScanOptions = {}): Promise<ScanResultSummary> {
  const config = opts.config ?? loadConfig();
  const store = opts.store ?? new SqliteStore(config.dbPath);
  const audit = opts.audit ?? new FileAuditSink('./data/audit.jsonl');
  const engine = await createEngine(config);

  const runId = `run-${Date.now()}`;
  store.createRun({ id: runId, engine: engine.id });
  await audit.append({
    actor: 'orchestrator',
    action: 'scan.start',
    runId,
    input: { target: opts.target ?? {}, engine: engine.id },
  });

  try {
    const collector = await runCollector({
      target: opts.target,
      onProgress: opts.onProgress,
    });

    store.saveInventory(runId, collector.inventory);

    await audit.append({
      actor: 'agent',
      agent: 'collector',
      action: 'scan.collected',
      runId,
      output: { stats: collector.stats, scanners: collector.scanResults.map(toScanAudit) },
    });

    // Phase 2 — Analyst: reachability + correlation + compliance (the core IP).
    const analyst = runAnalyst(
      { findings: collector.findings, inventory: collector.inventory },
      { onProgress: opts.onProgress },
    );

    // Persist the enriched (reachable / exploit-scored / control-mapped /
    // path-stamped) findings rather than the raw collector set.
    store.saveFindings(runId, analyst.findings);
    store.saveAttackPaths(runId, analyst.paths);

    await audit.append({
      actor: 'agent',
      agent: 'analyst',
      action: 'analyze.correlated',
      runId,
      output: {
        riskScore: analyst.riskScore,
        summary: analyst.summary,
        stats: analyst.stats,
        paths: analyst.paths.map(toPathAudit),
      },
    });

    // Phase 3 — Author: propose reviewable remediations (propose, don't apply).
    opts.onProgress?.('Proposing remediations (reviewable diffs / PRs)…');
    const proposals = proposeRemediations(analyst.findings, analyst.paths);

    await audit.append({
      actor: 'agent',
      agent: 'author',
      action: 'fixes.proposed',
      runId,
      output: {
        count: proposals.length,
        byPlaybook: tallyBy(proposals, (p) => p.playbookId),
        proposals: proposals.map(toFixAudit),
      },
    });

    store.finishRun(runId, {
      status: 'complete',
      usedFixtures: collector.stats.usedFixtures,
      findingCount: analyst.findings.length,
      pathCount: analyst.paths.length,
      riskScore: analyst.riskScore,
      summary: analyst.summary,
    });

    await audit.append({ actor: 'orchestrator', action: 'scan.complete', runId });

    return { run: store.getRun(runId)!, findings: analyst.findings, paths: analyst.paths, proposals };
  } catch (err) {
    store.finishRun(runId, { status: 'failed' });
    await audit.append({
      actor: 'orchestrator',
      action: 'scan.failed',
      runId,
      output: { error: (err as Error).message },
    });
    throw err;
  }
}

function toScanAudit(r: { source: string; usedFixture: boolean; durationMs: number; warning?: string }) {
  return { source: r.source, usedFixture: r.usedFixture, durationMs: r.durationMs, warning: r.warning };
}

function toPathAudit(p: AttackPath) {
  return { id: p.id, score: p.score, entryPoint: p.entryPoint, findingIds: p.findingIds };
}

function toFixAudit(p: RemediationProposal) {
  return {
    id: p.id,
    playbookId: p.playbookId,
    severity: p.severity,
    kind: p.kind,
    path: p.path,
    status: p.status,
    findingIds: p.findingIds,
  };
}

function tallyBy<T>(items: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const it of items) {
    const k = key(it);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}
