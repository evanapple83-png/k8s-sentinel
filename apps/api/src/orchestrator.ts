import { FileAuditSink, type AttackPath, type AuditSink, type Finding } from '@k8s-sentinel/core';
import { runCollector } from '@k8s-sentinel/agent-collector';
import { runAnalyst } from '@k8s-sentinel/agent-analyst';
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
}

/**
 * Orchestrates a full scan run: Collector (Phase 1) gathers + normalizes
 * findings, then the Analyst (Phase 2) enriches them with reachability,
 * correlates ranked attack paths, and maps compliance controls. Persists
 * findings + inventory + paths and writes the immutable audit trail. Holds no
 * cluster write creds (BUILD.md §4).
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

    store.finishRun(runId, {
      status: 'complete',
      usedFixtures: collector.stats.usedFixtures,
      findingCount: analyst.findings.length,
      pathCount: analyst.paths.length,
      riskScore: analyst.riskScore,
      summary: analyst.summary,
    });

    await audit.append({ actor: 'orchestrator', action: 'scan.complete', runId });

    return { run: store.getRun(runId)!, findings: analyst.findings, paths: analyst.paths };
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
