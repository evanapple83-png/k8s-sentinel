/**
 * @k8s-sentinel/agent-author — Agent 3, the reporter + remediation proposer.
 *
 * Composes the Analyst's ranked findings/attack-paths into audit-ready reports
 * (Markdown / JSON / HTML / PDF) and reviewable remediations (representative
 * manifest diffs + ready-to-open PR bodies). Propose-only: it never applies a
 * change. Pure/deterministic — runs offline with no model in the loop.
 */
export * from './diff.js';
export * from './playbooks.js';
export * from './remediation.js';
export * from './report.js';
export * from './pdf.js';
export * from './spec.js';
