import {
  fnv1a,
  sanitizeUntrusted,
  type AttackPath,
  type AttackStep,
  type ClusterInventory,
  type Finding,
  type WorkloadInfo,
} from '@k8s-sentinel/core';
import type { FindingContext } from './reachability.js';

/**
 * Correlation engine — the core IP (BUILD.md §3, Agent 2). Siloed findings are
 * fused into ranked attack-path narratives:
 *
 *   internet-exposed Service → running workload → exploitable vuln →
 *   over-privileged → can read a cluster Secret
 *
 * A path's `score` is reachability-weighted (it builds on each finding's
 * `exploitScore`), NOT a sum of CVSS values, so a dormant critical never
 * outranks a live, reachable chain.
 */

export interface CorrelationResult {
  paths: AttackPath[];
  /** finding id → attackPathId, for stamping findings. */
  findingToPath: Map<string, string>;
}

interface ScoredFinding {
  finding: Finding;
  ctx: FindingContext;
}

/**
 * Build attack paths from enriched findings + the cluster inventory. We group
 * findings by the workload they touch, then emit a path for every running
 * workload that is both reachable and either vulnerable or over-privileged.
 */
export function correlate(
  findings: Finding[],
  contexts: Map<string, FindingContext>,
  inventory: ClusterInventory,
): CorrelationResult {
  const byWorkload = groupByWorkload(findings, contexts);
  const paths: AttackPath[] = [];
  const findingToPath = new Map<string, string>();

  for (const [key, group] of byWorkload) {
    const workload = findWorkload(inventory, key);
    if (!workload) continue;
    const ctx = group[0]!.ctx; // every finding in the group shares the workload's facts

    if (!ctx.running) continue; // dormant workloads aren't a live path
    const vulnerable = group.some((g) => isVuln(g.finding));
    if (!ctx.exposed && !vulnerable && !ctx.overPrivileged) continue;
    // A meaningful chain needs reachability plus at least one risk amplifier.
    if (!(ctx.exposed && (vulnerable || ctx.overPrivileged))) continue;

    const steps = buildSteps(workload, ctx, group);
    const findingIds = group.map((g) => g.finding.id);
    const id = `path:${fnv1a(key)}`;
    const score = scorePath(group, ctx);
    const entryPoint = ctx.internetExposed ? 'internet' : ctx.exposed ? 'namespace' : 'in-cluster';

    paths.push({
      id,
      narrative: narrate(workload, ctx, group),
      steps,
      score,
      findingIds,
      entryPoint,
      createdAt: new Date().toISOString(),
    });
    for (const fid of findingIds) findingToPath.set(fid, id);
  }

  paths.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));
  return { paths, findingToPath };
}

// ---- steps ----------------------------------------------------------------

function buildSteps(w: WorkloadInfo, ctx: FindingContext, group: ScoredFinding[]): AttackStep[] {
  const ref = { namespace: w.namespace, kind: w.kind, name: w.name };
  const steps: AttackStep[] = [];

  if (ctx.exposed) {
    steps.push({
      kind: 'exposed',
      resource: ref,
      detail: ctx.internetExposed
        ? 'Reachable from outside the cluster via a LoadBalancer/NodePort Service.'
        : 'Reachable from within the namespace via a Service.',
      findingIds: group.filter((g) => g.finding.resource.kind === 'Service').map((g) => g.finding.id),
    });
  }

  steps.push({
    kind: 'running',
    resource: ref,
    detail: `${w.kind} ${w.namespace}/${w.name} is scheduled with ${w.replicas} replica(s).`,
    findingIds: [],
  });

  const vulns = group.filter((g) => isVuln(g.finding));
  if (vulns.length > 0) {
    const top = vulns
      .slice()
      .sort((a, b) => (b.finding.exploitScore ?? 0) - (a.finding.exploitScore ?? 0))[0]!;
    steps.push({
      kind: 'vulnerable',
      resource: top.finding.resource,
      detail: `Exploitable issue: ${cleanText(top.finding.ruleId)} (${top.finding.severity}).`,
      findingIds: vulns.map((g) => g.finding.id),
    });
  }

  if (ctx.overPrivileged) {
    steps.push({
      kind: 'over-privileged',
      resource: ref,
      detail: privilegeDetail(w),
      findingIds: group
        .filter((g) => g.finding.source === 'kubescape')
        .map((g) => g.finding.id),
    });
  }

  if (ctx.canReachSecret) {
    steps.push({
      kind: 'secret-access',
      resource: { ...ref, kind: 'ServiceAccount', name: w.serviceAccount },
      detail: `Service account "${w.serviceAccount}" can read cluster Secrets.`,
      findingIds: [],
    });
  }

  return steps;
}

function privilegeDetail(w: WorkloadInfo): string {
  const flags: string[] = [];
  if (w.privileged) flags.push('privileged');
  if (w.runAsRoot) flags.push('runs as root');
  if (w.allowPrivilegeEscalation) flags.push('allows privilege escalation');
  if (w.hostNetwork) flags.push('hostNetwork');
  if (w.hostPath) flags.push('hostPath mount');
  return flags.length > 0
    ? `Over-privileged: ${flags.join(', ')}.`
    : 'Bound to an over-privileged service account.';
}

// ---- scoring --------------------------------------------------------------

/** Reachability-weighted path score in [0,100]. Builds on finding exploitScores. */
export function scorePath(group: ScoredFinding[], ctx: FindingContext): number {
  const maxExploit = Math.max(0, ...group.map((g) => g.finding.exploitScore ?? 0));
  const kinds = new Set<string>();
  if (ctx.exposed) kinds.add('exposed');
  kinds.add('running');
  if (group.some((g) => isVuln(g.finding))) kinds.add('vulnerable');
  if (ctx.overPrivileged) kinds.add('over-privileged');
  if (ctx.canReachSecret) kinds.add('secret-access');

  const lengthBonus = kinds.size * 4;
  const terminalBonus = (ctx.canReachSecret ? 12 : 0) + (ctx.internetExposed ? 8 : 0);
  return Math.max(0, Math.min(100, Math.round(maxExploit * 0.7 + lengthBonus + terminalBonus)));
}

// ---- narrative ------------------------------------------------------------

function narrate(w: WorkloadInfo, ctx: FindingContext, group: ScoredFinding[]): string {
  const where = `${w.kind} ${w.namespace}/${w.name}`;
  const parts: string[] = [];

  if (ctx.internetExposed) parts.push(`Internet-exposed ${where}`);
  else if (ctx.exposed) parts.push(`Namespace-reachable ${where}`);
  else parts.push(where);

  parts.push(`is running (${w.replicas} replica(s))`);

  const vulns = group
    .filter((g) => isVuln(g.finding))
    .sort((a, b) => (b.finding.exploitScore ?? 0) - (a.finding.exploitScore ?? 0));
  if (vulns.length > 0) {
    const lead = vulns[0]!.finding;
    const extra = vulns.length > 1 ? ` and ${vulns.length - 1} more` : '';
    parts.push(`carries a ${lead.severity} vulnerability ${cleanText(lead.ruleId)}${extra}`);
  }

  if (ctx.privileged || ctx.runAsRoot) {
    parts.push(`runs ${[ctx.privileged ? 'privileged' : '', ctx.runAsRoot ? 'as root' : ''].filter(Boolean).join(' and ')}`);
  } else if (ctx.overPrivileged) {
    parts.push('is over-privileged');
  }

  if (ctx.canReachSecret) {
    parts.push(`and its service account "${w.serviceAccount}" can read cluster Secrets`);
  }

  const tail = ctx.canReachSecret
    ? ' — a full external-to-secret attack path.'
    : ctx.internetExposed
      ? ' — exploitable from outside the cluster.'
      : '.';

  return parts.join(', ').replace(/, and /g, ' and ') + tail;
}

// ---- helpers --------------------------------------------------------------

function isVuln(f: Finding): boolean {
  // Image CVEs (Trivy) and high-signal runtime detections (Falco critical/high)
  // are the "exploitable" links in a chain.
  return f.source === 'trivy' || (f.source === 'falco' && (f.severity === 'critical' || f.severity === 'high'));
}

function groupByWorkload(
  findings: Finding[],
  contexts: Map<string, FindingContext>,
): Map<string, ScoredFinding[]> {
  const groups = new Map<string, ScoredFinding[]>();
  for (const finding of findings) {
    const ctx = contexts.get(finding.id);
    if (!ctx?.linked || !ctx.workload) continue;
    const key = `${ctx.workload.namespace ?? ''}/${ctx.workload.name}`;
    const arr = groups.get(key) ?? [];
    arr.push({ finding, ctx });
    groups.set(key, arr);
  }
  return groups;
}

function findWorkload(inv: ClusterInventory, key: string): WorkloadInfo | undefined {
  const slash = key.indexOf('/');
  const ns = key.slice(0, slash);
  const name = key.slice(slash + 1);
  return inv.workloads.find((w) => w.namespace === ns && w.name === name);
}

/** Defang scanner-controlled text (CVE ids, rule names) before it lands in product output. */
function cleanText(s: string): string {
  return sanitizeUntrusted(s, { fence: false, maxLength: 120 });
}
