import {
  sanitizeUntrusted,
  SEVERITIES,
  type AttackPath,
  type Finding,
  type Severity,
} from '@k8s-sentinel/core';
import type { RemediationProposal } from './remediation.js';

/**
 * Audit-ready report (BUILD.md Feature 3). `buildReport` produces one
 * structured, injection-safe model; the renderers turn it into Markdown, JSON,
 * HTML, or PDF. Every string that originated from a scanner is sanitized here,
 * once, before it can reach any output format.
 */

export type PostureRating = 'critical' | 'elevated' | 'moderate' | 'low';

export interface ReportInput {
  runId: string;
  engine: string;
  usedFixtures: boolean;
  riskScore: number;
  summary: string;
  findings: Finding[];
  paths?: AttackPath[];
  proposals?: RemediationProposal[];
  generatedAt?: string;
}

export interface SecurityReport {
  tool: 'K8s Sentinel';
  meta: { runId: string; generatedAt: string; engine: string; usedFixtures: boolean };
  posture: {
    riskScore: number;
    rating: PostureRating;
    summary: string;
    totalFindings: number;
    reachableFindings: number;
    bySeverity: Record<Severity, number>;
    bySource: Record<string, number>;
  };
  attackPaths: Array<{
    id: string;
    score: number;
    entryPoint: string;
    narrative: string;
    steps: Array<{ kind: string; resource: string; detail: string }>;
  }>;
  topFindings: Array<{
    id: string;
    severity: Severity;
    source: string;
    ruleId: string;
    title: string;
    resource: string;
    reachable: boolean;
    exploitScore: number;
    controls: string[];
  }>;
  compliance: Array<{ framework: string; controls: string[]; findingCount: number }>;
  remediations: Array<{
    id: string;
    title: string;
    severity: Severity;
    kind: string;
    rationale: string;
    path: string;
    controls: string[];
    status: string;
  }>;
}

const TOP_FINDINGS = 15;

export function buildReport(input: ReportInput): SecurityReport {
  const findings = [...input.findings].sort(
    (a, b) => (b.exploitScore ?? 0) - (a.exploitScore ?? 0),
  );
  const paths = input.paths ?? [];
  const proposals = input.proposals ?? [];

  return {
    tool: 'K8s Sentinel',
    meta: {
      runId: input.runId,
      generatedAt: input.generatedAt ?? new Date().toISOString(),
      engine: input.engine,
      usedFixtures: input.usedFixtures,
    },
    posture: {
      riskScore: input.riskScore,
      rating: rate(input.riskScore),
      summary: safe(input.summary, 300),
      totalFindings: findings.length,
      reachableFindings: findings.filter((f) => f.reachable).length,
      bySeverity: tally(findings, (f) => f.severity) as Record<Severity, number>,
      bySource: tally(findings, (f) => f.source),
    },
    attackPaths: paths.map((p) => ({
      id: p.id,
      score: p.score,
      entryPoint: safe(p.entryPoint ?? 'in-cluster', 40),
      narrative: safe(p.narrative, 600),
      steps: p.steps.map((s) => ({
        kind: s.kind,
        resource: resourceLabel(s.resource),
        detail: safe(s.detail, 200),
      })),
    })),
    topFindings: findings.slice(0, TOP_FINDINGS).map((f) => ({
      id: f.id,
      severity: f.severity,
      source: f.source,
      ruleId: safe(f.ruleId, 60),
      title: safe(f.title, 160),
      resource: resourceLabel(f.resource),
      reachable: Boolean(f.reachable),
      exploitScore: f.exploitScore ?? 0,
      controls: (f.controls ?? []).map((c) => c.id),
    })),
    compliance: complianceRollup(findings),
    remediations: proposals.map((p) => ({
      id: p.id,
      title: p.title,
      severity: p.severity,
      kind: p.kind,
      rationale: p.rationale,
      path: p.path,
      controls: p.controls.map((c) => c.id),
      status: p.status,
    })),
  };
}

// ---- Markdown --------------------------------------------------------------

export function renderMarkdown(r: SecurityReport): string {
  const L: string[] = [];
  L.push(`# K8s Sentinel — Security Report`);
  L.push('');
  L.push(
    `**Run:** \`${r.meta.runId}\`  ·  **Generated:** ${r.meta.generatedAt}  ·  **Engine:** ${r.meta.engine}` +
      (r.meta.usedFixtures ? '  ·  _offline fixtures_' : ''),
  );
  L.push('');
  L.push(`## Posture — ${r.posture.riskScore}/100 (${r.posture.rating})`);
  L.push('');
  L.push(r.posture.summary);
  L.push('');
  L.push(`- **Findings:** ${r.posture.totalFindings} (${r.posture.reachableFindings} reachable)`);
  L.push(
    `- **By severity:** ` +
      SEVERITIES.filter((s) => r.posture.bySeverity[s]).map((s) => `${r.posture.bySeverity[s]} ${s}`).join(', '),
  );
  L.push(
    `- **By scanner:** ` +
      Object.entries(r.posture.bySource).map(([s, n]) => `${n} ${s}`).join(', '),
  );

  L.push('');
  L.push(`## Attack paths (${r.attackPaths.length})`);
  if (r.attackPaths.length === 0) L.push('\n_No correlated attack paths — nothing both reachable and exploitable._');
  for (const p of r.attackPaths) {
    L.push('');
    L.push(`### ${p.score}/100 — from ${p.entryPoint}`);
    L.push(p.narrative);
    L.push('');
    L.push(p.steps.map((s) => `\`${s.kind}\``).join(' → '));
  }

  L.push('');
  L.push(`## Top findings (by exploitability)`);
  L.push('');
  L.push('| Score | Sev | Reach | Source | Finding | Resource |');
  L.push('|------:|-----|:-----:|--------|---------|----------|');
  for (const f of r.topFindings) {
    L.push(
      `| ${f.exploitScore} | ${f.severity} | ${f.reachable ? '✓' : ''} | ${f.source} | ${mdCell(f.title)} | ${mdCell(f.resource)} |`,
    );
  }

  if (r.compliance.length) {
    L.push('');
    L.push(`## Compliance`);
    L.push('');
    for (const c of r.compliance) {
      L.push(`- **${c.framework}** — ${c.findingCount} finding(s): ${c.controls.map((x) => `\`${x}\``).join(', ')}`);
    }
  }

  L.push('');
  L.push(`## Recommended remediations (${r.remediations.length})`);
  if (r.remediations.length === 0) L.push('\n_None proposed._');
  for (const m of r.remediations) {
    L.push('');
    L.push(`### ${m.title} — ${m.severity}`);
    L.push(`_${m.kind} · \`${m.path}\` · ${m.status}_`);
    L.push('');
    L.push(m.rationale);
    if (m.controls.length) L.push(`\nControls: ${m.controls.map((x) => `\`${x}\``).join(', ')}`);
  }

  L.push('');
  L.push('---');
  L.push('_Generated by K8s Sentinel. Read-only by design; all fixes require human approval._');
  return L.join('\n') + '\n';
}

// ---- JSON ------------------------------------------------------------------

export function renderJson(r: SecurityReport): string {
  return JSON.stringify(r, null, 2) + '\n';
}

// ---- HTML (Apple-like, printable) -----------------------------------------

export function renderHtml(r: SecurityReport): string {
  const sevRow = SEVERITIES.filter((s) => r.posture.bySeverity[s])
    .map((s) => `<span class="pill ${s}">${r.posture.bySeverity[s]} ${s}</span>`)
    .join(' ');

  const paths = r.attackPaths.length
    ? r.attackPaths
        .map(
          (p) => `
      <div class="card">
        <div class="row"><span class="score ${ratingForScore(p.score)}">${p.score}</span>
          <span class="muted">from ${esc(p.entryPoint)}</span></div>
        <p>${esc(p.narrative)}</p>
        <div class="chain">${p.steps.map((s) => `<span class="step">${esc(s.kind)}</span>`).join('<span class="arrow">→</span>')}</div>
      </div>`,
        )
        .join('')
    : `<p class="muted">No correlated attack paths.</p>`;

  const findings = r.topFindings
    .map(
      (f) => `
      <tr>
        <td class="num">${f.exploitScore}</td>
        <td><span class="dot ${f.severity}"></span>${f.severity}</td>
        <td>${f.reachable ? '<span class="reach">reachable</span>' : ''}</td>
        <td class="muted">${esc(f.source)}</td>
        <td>${esc(f.title)}</td>
        <td class="muted">${esc(f.resource)}</td>
      </tr>`,
    )
    .join('');

  const fixes = r.remediations.length
    ? r.remediations
        .map(
          (m) => `
      <div class="card">
        <div class="row"><strong>${esc(m.title)}</strong><span class="pill ${m.severity}">${m.severity}</span></div>
        <p>${esc(m.rationale)}</p>
        <div class="muted mono">${esc(m.kind)} · ${esc(m.path)} · ${esc(m.status)}</div>
      </div>`,
        )
        .join('')
    : `<p class="muted">None proposed.</p>`;

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>K8s Sentinel — Security Report</title>
<style>
  :root{--bg:#FBFBFD;--surface:#fff;--text:#1D1D1F;--muted:#6E6E73;--accent:#0A84FF;
    --clear:#34C759;--warn:#FF9F0A;--critical:#FF3B30;--radius:16px;--shadow:0 8px 30px rgba(0,0,0,.06)}
  @media (prefers-color-scheme:dark){:root{--bg:#0B0B0F;--surface:#1C1C1E;--text:#F5F5F7;--muted:#9b9ba1}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
    font:16px/1.55 -apple-system,BlinkMacSystemFont,"SF Pro Text","Inter",system-ui,sans-serif;
    -webkit-font-smoothing:antialiased}
  main{max-width:880px;margin:0 auto;padding:56px 28px 96px}
  h1{font-size:34px;letter-spacing:-.02em;margin:0 0 4px}
  h2{font-size:13px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin:48px 0 14px}
  .muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
  .meta{color:var(--muted);font-size:14px;margin-bottom:8px}
  .hero{display:flex;align-items:center;gap:28px;margin-top:28px;padding:28px;background:var(--surface);
    border-radius:var(--radius);box-shadow:var(--shadow)}
  .ring{--v:0;width:128px;height:128px;border-radius:50%;flex:none;display:grid;place-items:center;
    background:conic-gradient(var(--ring) calc(var(--v)*1%),rgba(127,127,127,.15) 0)}
  .ring>div{width:104px;height:104px;border-radius:50%;background:var(--surface);display:grid;place-items:center;
    font-size:32px;font-weight:600}
  .rating{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
  .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;background:rgba(127,127,127,.14);margin:2px 0}
  .pill.critical{background:rgba(255,59,48,.16);color:var(--critical)}
  .pill.high{background:rgba(255,99,71,.16)}.pill.medium{background:rgba(255,159,10,.18)}
  .pill.low,.pill.info{background:rgba(52,199,89,.16)}
  .card{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);padding:18px 20px;margin:12px 0}
  .row{display:flex;align-items:center;gap:12px;justify-content:space-between}
  .score{font-weight:700}.score.critical{color:var(--critical)}.score.elevated{color:var(--warn)}
  .score.moderate{color:var(--warn)}.score.low{color:var(--clear)}
  .chain{margin-top:10px;display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .step{background:rgba(10,132,255,.12);color:var(--accent);border-radius:8px;padding:2px 10px;font-size:13px}
  .arrow{color:var(--muted)}
  table{width:100%;border-collapse:collapse;font-size:14px}
  td{padding:9px 8px;border-bottom:1px solid rgba(127,127,127,.14);vertical-align:top}
  .num{font-variant-numeric:tabular-nums;color:var(--muted)}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;background:var(--muted)}
  .dot.critical{background:var(--critical)}.dot.high{background:#ff6347}.dot.medium{background:var(--warn)}
  .dot.low,.dot.info{background:var(--clear)}
  .reach{font-size:12px;color:var(--critical)}
  footer{margin-top:56px;color:var(--muted);font-size:13px;border-top:1px solid rgba(127,127,127,.14);padding-top:16px}
</style></head>
<body><main>
  <h1>Security Report</h1>
  <div class="meta">Run <span class="mono">${esc(r.meta.runId)}</span> · ${esc(r.meta.generatedAt)} · engine ${esc(r.meta.engine)}${r.meta.usedFixtures ? ' · offline fixtures' : ''}</div>
  <div class="hero">
    <div class="ring" style="--v:${r.posture.riskScore};--ring:${ringColor(r.posture.rating)}"><div>${r.posture.riskScore}</div></div>
    <div>
      <div class="rating">${r.posture.rating} risk</div>
      <p style="margin:6px 0 10px">${esc(r.posture.summary)}</p>
      <div>${sevRow}</div>
    </div>
  </div>

  <h2>Attack paths (${r.attackPaths.length})</h2>
  ${paths}

  <h2>Top findings — by exploitability</h2>
  <table><tbody>${findings}</tbody></table>

  <h2>Recommended remediations (${r.remediations.length})</h2>
  ${fixes}

  <footer>Generated by K8s Sentinel · Author agent. Read-only by design; all fixes require human approval.</footer>
</main></body></html>
`;
}

// ---- shared helpers --------------------------------------------------------

export function rate(score: number): PostureRating {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'elevated';
  if (score >= 20) return 'moderate';
  return 'low';
}

function ratingForScore(score: number): PostureRating {
  return rate(score);
}

function ringColor(rating: PostureRating): string {
  return rating === 'critical' ? '#FF3B30' : rating === 'low' ? '#34C759' : '#FF9F0A';
}

function resourceLabel(r: { kind: string; namespace?: string; name: string; image?: string }): string {
  const ns = r.namespace ? `${safe(r.namespace, 60)}/` : '';
  const img = r.image ? ` (${safe(r.image, 80)})` : '';
  return `${safe(r.kind, 40)} ${ns}${safe(r.name, 80)}${img}`;
}

function complianceRollup(findings: Finding[]): SecurityReport['compliance'] {
  const map = new Map<string, { controls: Set<string>; count: number }>();
  for (const f of findings) {
    const seenFw = new Set<string>();
    for (const c of f.controls ?? []) {
      const entry = map.get(c.framework) ?? { controls: new Set(), count: 0 };
      entry.controls.add(c.id);
      if (!seenFw.has(c.framework)) {
        entry.count += 1;
        seenFw.add(c.framework);
      }
      map.set(c.framework, entry);
    }
  }
  return [...map.entries()]
    .map(([framework, v]) => ({ framework, controls: [...v.controls].sort(), findingCount: v.count }))
    .sort((a, b) => b.findingCount - a.findingCount);
}

function tally<T>(items: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const it of items) {
    const k = key(it);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function safe(value: unknown, maxLength = 200): string {
  return sanitizeUntrusted(String(value ?? ''), { fence: false, maxLength }).trim();
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

function mdCell(s: string): string {
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ');
}
