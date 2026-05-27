import type { ClusterInventory, Finding } from '@k8s-sentinel/core';
import { runAllScanners, type ScanResult, type ScanTarget } from '@k8s-sentinel/tools-mcp';
import { collectInventory } from './inventory.js';

export interface CollectorOptions {
  target?: ScanTarget;
  /** Progress callback for streaming to the UI / audit log. */
  onProgress?: (msg: string) => void;
}

export interface CollectorOutput {
  inventory: ClusterInventory;
  findings: Finding[];
  scanResults: ScanResult[];
  stats: {
    totalFindings: number;
    bySource: Record<string, number>;
    bySeverity: Record<string, number>;
    usedFixtures: boolean;
  };
}

/**
 * Run Agent 1. Inventory + the four scanners execute concurrently; their
 * findings are merged and de-duplicated by stable id. Deterministic by design —
 * the heavy lifting is code, not the model, so it runs offline against fixtures.
 */
export async function runCollector(opts: CollectorOptions = {}): Promise<CollectorOutput> {
  const { target = {}, onProgress } = opts;
  onProgress?.('Connecting (read-only) and starting parallel scan…');

  const [inventory, scan] = await Promise.all([collectInventory(target), runAllScanners(target)]);

  const findings = dedupeById(scan.findings);
  onProgress?.(
    `Collected ${findings.length} findings across ${scan.results.length} scanners ` +
      `(${inventory.workloads.length} workloads, ${inventory.services.length} services).`,
  );

  return { inventory, findings, scanResults: scan.results, stats: summarize(findings, scan.results) };
}

function dedupeById(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const f of findings) if (!seen.has(f.id)) seen.set(f.id, f);
  return [...seen.values()];
}

function summarize(findings: Finding[], results: ScanResult[]): CollectorOutput['stats'] {
  const bySource: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  for (const f of findings) {
    bySource[f.source] = (bySource[f.source] ?? 0) + 1;
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }
  return {
    totalFindings: findings.length,
    bySource,
    bySeverity,
    usedFixtures: results.some((r) => r.usedFixture),
  };
}
