import {
  fnv1a,
  sanitizeUntrusted,
  SEVERITY_WEIGHT,
  type AttackPath,
  type ControlRef,
  type Finding,
  type Severity,
} from '@k8s-sentinel/core';
import { findPlaybook, type RemediationKind } from './playbooks.js';

/**
 * Turns ranked findings/attack-paths into reviewable remediation proposals
 * (BUILD.md Feature 5 — "human-on-the-loop fixes"). A proposal is never
 * applied: it carries a representative manifest diff and a ready-to-open PR
 * body that a human reviews and approves. Deterministic and offline.
 */

export interface RemediationProposal {
  /** Stable id derived from (playbook, target path) — survives re-scans. */
  id: string;
  playbookId: string;
  title: string;
  severity: Severity;
  kind: RemediationKind;
  /** Injection-safe explanation. */
  rationale: string;
  /** Representative manifest path. */
  path: string;
  /** Unified diff (empty for manual playbooks). */
  diff: string;
  manualSteps: string[];
  controls: ControlRef[];
  /** Findings this single proposal resolves. */
  findingIds: string[];
  attackPathId?: string;
  /** Address-first ranking: higher = more urgent. */
  priority: number;
  /** Proposals are emitted, not applied. */
  status: 'proposed';
  /** Suggested git branch + PR metadata. */
  branch: string;
  prTitle: string;
  prBody: string;
  createdAt: string;
}

export interface ProposeOptions {
  /** Cap the number of proposals (most urgent first). Default 12. */
  limit?: number;
  /** Override the timestamp (tests/determinism). */
  now?: string;
}

interface Group {
  representative: Finding;
  findings: Finding[];
  attackPathId?: string;
  maxExploit: number;
  anyReachable: boolean;
}

/**
 * Propose remediations, most urgent first. Findings are grouped per
 * (playbook, target manifest) so two CVEs on one image — or two checks on one
 * Deployment — collapse into a single reviewable PR.
 */
export function proposeRemediations(
  findings: Finding[],
  paths: AttackPath[] = [],
  opts: ProposeOptions = {},
): RemediationProposal[] {
  const { limit = 12, now = new Date().toISOString() } = opts;
  const pathScore = new Map(paths.map((p) => [p.id, p.score] as const));

  const groups = new Map<string, Group>();
  for (const f of findings) {
    const pb = findPlaybook(f);
    if (!pb) continue;
    const { path } = pb.build(f);
    const key = `${pb.id}::${path}`;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, {
        representative: f,
        findings: [f],
        attackPathId: f.attackPathId,
        maxExploit: f.exploitScore ?? 0,
        anyReachable: Boolean(f.reachable),
      });
    } else {
      g.findings.push(f);
      g.attackPathId ??= f.attackPathId;
      if ((f.exploitScore ?? 0) > (g.representative.exploitScore ?? 0)) g.representative = f;
      g.maxExploit = Math.max(g.maxExploit, f.exploitScore ?? 0);
      g.anyReachable ||= Boolean(f.reachable);
    }
  }

  const proposals: RemediationProposal[] = [];
  for (const [key, g] of groups) {
    const pb = findPlaybook(g.representative)!;
    const fix = pb.build(g.representative);
    const severity = worstSeverity(g.findings);
    const controls = mergeControls(g.findings);
    // Address-first: reachability-weighted exploit score, lifted for paths.
    const onLivePath = g.attackPathId ? (pathScore.get(g.attackPathId) ?? 0) : 0;
    const priority = Math.round(
      g.maxExploit + (g.anyReachable ? 5 : 0) + onLivePath * 0.2 + pb.priority * 0.1,
    );
    const id = `fix:${fnv1a(key)}`;
    const branch = makeBranch(pb.id, fix.path);
    const prTitle = `[K8s Sentinel] ${pb.title} — ${describeTarget(g.representative)}`;

    proposals.push({
      id,
      playbookId: pb.id,
      title: pb.title,
      severity,
      kind: fix.kind,
      rationale: fix.rationale,
      path: fix.path,
      diff: fix.diff,
      manualSteps: fix.manualSteps,
      controls,
      findingIds: g.findings.map((f) => f.id),
      attackPathId: g.attackPathId,
      priority,
      status: 'proposed',
      branch,
      prTitle,
      prBody: renderPrBody({ pb, fix, severity, controls, group: g, onLivePath }),
      createdAt: now,
    });
  }

  proposals.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id));
  return proposals.slice(0, limit);
}

/** A reviewable PR payload. Building it never opens or applies anything. */
export interface PrBundle {
  proposalId: string;
  branch: string;
  title: string;
  body: string;
  /** Patches to apply on the branch. Empty for manual proposals. */
  files: Array<{ path: string; diff: string }>;
  createdAt: string;
}

export function buildPrBundle(p: RemediationProposal): PrBundle {
  return {
    proposalId: p.id,
    branch: p.branch,
    title: p.prTitle,
    body: p.prBody,
    files: p.diff ? [{ path: p.path, diff: p.diff }] : [],
    createdAt: p.createdAt,
  };
}

// ---- helpers ---------------------------------------------------------------

function worstSeverity(findings: Finding[]): Severity {
  let worst: Severity = 'info';
  for (const f of findings) {
    if (SEVERITY_WEIGHT[f.severity] > SEVERITY_WEIGHT[worst]) worst = f.severity;
  }
  return worst;
}

function mergeControls(findings: Finding[]): ControlRef[] {
  const seen = new Map<string, ControlRef>();
  for (const f of findings) for (const c of f.controls ?? []) if (!seen.has(c.id)) seen.set(c.id, c);
  return [...seen.values()];
}

function describeTarget(f: Finding): string {
  const r = f.resource;
  const ns = r.namespace ? `${safe(r.namespace, 60)}/` : '';
  return `${safe(r.kind, 40)} ${ns}${safe(r.name, 80)}`;
}

function makeBranch(playbookId: string, path: string): string {
  const slug = (path.split('/').pop() ?? path)
    .replace(/\.(ya?ml|md)$/i, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return `sentinel/fix/${playbookId}-${slug}`.slice(0, 100);
}

function safe(value: unknown, maxLength = 160): string {
  return sanitizeUntrusted(String(value ?? ''), { fence: false, maxLength }).trim();
}

function renderPrBody(args: {
  pb: { id: string; title: string };
  fix: { rationale: string; kind: RemediationKind; manualSteps: string[]; diff: string; path: string };
  severity: Severity;
  controls: ControlRef[];
  group: Group;
  onLivePath: number;
}): string {
  const { pb, fix, severity, controls, group, onLivePath } = args;
  const lines: string[] = [];
  lines.push(`## ${pb.title}`);
  lines.push('');
  lines.push(`> Proposed by **K8s Sentinel** — review and approve before applying. Nothing was changed in your cluster.`);
  lines.push('');
  lines.push(`**Severity:** ${severity.toUpperCase()}  ·  **Playbook:** \`${pb.id}\``);
  if (onLivePath > 0) lines.push(`**On a live attack path** (path risk ${onLivePath}/100).`);
  lines.push('');
  lines.push('### Why');
  lines.push(fix.rationale);
  lines.push('');
  lines.push('### Findings addressed');
  for (const f of group.findings) {
    lines.push(`- \`${safe(f.ruleId, 40)}\` [${f.source}] — ${safe(f.title, 120)}`);
  }
  if (controls.length) {
    lines.push('');
    lines.push('### Controls satisfied');
    lines.push(controls.map((c) => `\`${c.id}\``).join(' · '));
  }
  if (fix.diff) {
    lines.push('');
    lines.push(`### Proposed change — \`${fix.path}\``);
    lines.push('_Representative manifest; adapt to your source of truth._');
    lines.push('');
    lines.push('```diff');
    lines.push(fix.diff.trimEnd());
    lines.push('```');
  }
  if (fix.manualSteps.length) {
    lines.push('');
    lines.push('### Steps');
    fix.manualSteps.forEach((s, i) => lines.push(`${i + 1}. ${s}`));
  }
  lines.push('');
  lines.push('---');
  lines.push('_Generated by K8s Sentinel · Author agent. Read-only by design; this PR requires human approval._');
  return lines.join('\n');
}
