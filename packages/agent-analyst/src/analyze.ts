import type { AttackPath, ClusterInventory, Finding } from '@k8s-sentinel/core';
import { analyzeReachability, type FindingContext } from './reachability.js';
import { complianceSummary, withControls } from './compliance.js';
import { correlate } from './correlate.js';

/**
 * Agent 2 — the Analyst (BUILD.md §3). Ties the three deterministic stages into
 * one pass over the Collector's output:
 *
 *   1. reachability  — enrich each finding with `reachable` + `exploitScore`
 *                      (reachability-weighted, NOT raw CVSS) + per-finding context
 *   2. compliance    — map every finding to CIS / NSA-CISA / SOC 2 / MITRE controls
 *   3. correlation   — fuse findings into ranked `AttackPath[]` (the core IP)
 *
 * Pure and deterministic, so the whole Analyst runs offline against fixtures
 * with no model in the loop. The engine-backed agent wraps this for the
 * narrative/NL layer, but the verdicts are reproducible.
 */

export interface AnalystInput {
  findings: Finding[];
  inventory: ClusterInventory;
}

export interface AnalystStats {
  totalFindings: number;
  reachableFindings: number;
  pathCount: number;
  bySeverity: Record<string, number>;
  /** Findings touching each compliance framework. */
  compliance: Record<string, number>;
}

export interface AnalystOutput {
  /** Findings enriched with reachable/exploitScore/controls/attackPathId, ranked. */
  findings: Finding[];
  /** Correlated attack paths, ranked by reachability-weighted score. */
  paths: AttackPath[];
  /** Per-finding reachability context (drives the NL query engine). */
  contexts: Map<string, FindingContext>;
  /** Overall posture risk in [0,100] for the dashboard ring. */
  riskScore: number;
  /** One-line, injection-safe posture summary. */
  summary: string;
  /** Namespaces seen (passed to the query engine to resolve "in <ns>"). */
  namespaces: string[];
  stats: AnalystStats;
}

export interface AnalystOptions {
  onProgress?: (msg: string) => void;
}

export function runAnalyst(input: AnalystInput, opts: AnalystOptions = {}): AnalystOutput {
  const { onProgress } = opts;

  onProgress?.('Analyzing reachability (running · exposed · over-privileged · secret-reach)…');
  const { findings: reached, contexts } = analyzeReachability(input.findings, input.inventory);

  const withCtl = withControls(reached);

  onProgress?.('Correlating findings into ranked attack paths…');
  const { paths, findingToPath } = correlate(withCtl, contexts, input.inventory);

  // Stamp each finding with the path it participates in (order preserved → still
  // reachability-ranked from analyzeReachability).
  const findings = withCtl.map((f) => {
    const pid = findingToPath.get(f.id);
    return pid ? { ...f, attackPathId: pid } : f;
  });

  const riskScore = computeRisk(findings, paths);
  const summary = buildSummary(findings, paths);

  onProgress?.(
    `Correlated ${paths.length} attack path(s); posture risk ${riskScore}/100.`,
  );

  return {
    findings,
    paths,
    contexts,
    riskScore,
    summary,
    namespaces: input.inventory.namespaces,
    stats: {
      totalFindings: findings.length,
      reachableFindings: findings.filter((f) => f.reachable).length,
      pathCount: paths.length,
      bySeverity: tallyBy(findings, (f) => f.severity),
      compliance: complianceSummary(findings),
    },
  };
}

/**
 * Overall posture risk in [0,100]. Anchored on the worst *live* attack path
 * (reachability already baked into both scores), nudged for breadth (multiple
 * paths) and for reachable criticals — never a raw sum of CVSS.
 */
export function computeRisk(findings: Finding[], paths: AttackPath[]): number {
  const topPath = paths[0]?.score ?? 0;
  const topFinding = findings[0]?.exploitScore ?? 0; // findings are exploit-ranked
  const breadthBonus = Math.min(10, Math.max(0, paths.length - 1) * 3);
  const reachableCriticals = findings.filter((f) => f.reachable && f.severity === 'critical').length;
  const criticalBonus = Math.min(8, reachableCriticals * 2);
  return clamp(Math.round(Math.max(topPath, topFinding) + breadthBonus + criticalBonus));
}

/** Injection-safe (numbers/enums only — no untrusted scanner text). */
function buildSummary(findings: Finding[], paths: AttackPath[]): string {
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const reachable = findings.filter((f) => f.reachable).length;
  const base = `${findings.length} findings (${critical} critical, ${reachable} reachable)`;
  const lead = paths[0];
  if (!lead) return `${base}; no live attack paths.`;
  return (
    `${base}; ${paths.length} correlated attack path${paths.length === 1 ? '' : 's'}` +
    `; highest-risk path scores ${lead.score}/100 from ${lead.entryPoint ?? 'in-cluster'}.`
  );
}

function tallyBy<T>(items: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const it of items) {
    const k = key(it);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, n));
}
