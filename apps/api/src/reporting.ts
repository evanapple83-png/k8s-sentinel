import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { FileAuditSink, type AttackPath, type Finding } from '@k8s-sentinel/core';
import {
  buildPrBundle,
  buildReport,
  proposeRemediations,
  renderHtml,
  renderJson,
  renderMarkdown,
  renderPdf,
  type PrBundle,
  type RemediationProposal,
  type SecurityReport,
} from '@k8s-sentinel/agent-author';
import { SqliteStore, type RunRecord } from './store.js';

/**
 * Shared Author-facing helpers (Phase 3). The CLI and the HTTP server both go
 * through here so report rendering and the "approve → PR bundle" flow behave
 * identically. Remediations are regenerated deterministically from the stored
 * run, so proposal ids are stable; approvals are recorded in the immutable
 * audit log (the source of truth for "which fixes were approved").
 */

export const AUDIT_PATH = './data/audit.jsonl';
export const PR_DIR = './data/prs';

export function auditSink(): FileAuditSink {
  return new FileAuditSink(AUDIT_PATH);
}

export interface RunBundle {
  run: RunRecord;
  findings: Finding[];
  paths: AttackPath[];
}

export function loadRun(store: SqliteStore, runId: string): RunBundle | undefined {
  const run = store.getRun(runId);
  if (!run) return undefined;
  return { run, findings: store.getFindings(runId), paths: store.getAttackPaths(runId) };
}

export function proposalsForRun(b: RunBundle): RemediationProposal[] {
  return proposeRemediations(b.findings, b.paths);
}

export function reportForRun(b: RunBundle): SecurityReport {
  return buildReport({
    runId: b.run.id,
    engine: b.run.engine,
    usedFixtures: b.run.usedFixtures,
    riskScore: b.run.riskScore ?? 0,
    summary: b.run.summary ?? '',
    findings: b.findings,
    paths: b.paths,
    proposals: proposalsForRun(b),
  });
}

export type ReportFormat = 'md' | 'json' | 'html' | 'pdf';

export function renderReport(
  r: SecurityReport,
  fmt: ReportFormat,
): { body: string | Uint8Array; contentType: string; ext: ReportFormat } {
  switch (fmt) {
    case 'json':
      return { body: renderJson(r), contentType: 'application/json', ext: 'json' };
    case 'html':
      return { body: renderHtml(r), contentType: 'text/html; charset=utf-8', ext: 'html' };
    case 'pdf':
      return { body: renderPdf(r), contentType: 'application/pdf', ext: 'pdf' };
    case 'md':
    default:
      return { body: renderMarkdown(r), contentType: 'text/markdown; charset=utf-8', ext: 'md' };
  }
}

export interface ApprovalResult {
  proposalId: string;
  dir: string;
  bundle: PrBundle;
}

/**
 * Approve a proposed fix. Writes a reviewable PR bundle (description + patch)
 * to disk and records the approval in the audit log. It NEVER applies the
 * change or pushes to a remote — a human takes it from here (BUILD.md §10).
 */
export async function approveFix(args: {
  store: SqliteStore;
  runId: string;
  fixId: string;
  actor?: 'user' | 'agent';
  outDir?: string;
}): Promise<ApprovalResult | undefined> {
  const b = loadRun(args.store, args.runId);
  if (!b) return undefined;
  const proposal = proposalsForRun(b).find((p) => p.id === args.fixId);
  if (!proposal) return undefined;

  const bundle = buildPrBundle(proposal);
  const dir = join(args.outDir ?? PR_DIR, proposal.id.replace(/[^a-z0-9_-]/gi, '-'));
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, 'PR.md'),
    `# ${bundle.title}\n\n**Branch:** \`${bundle.branch}\`\n\n${bundle.body}\n`,
    'utf8',
  );
  if (bundle.files.length) {
    writeFileSync(join(dir, 'changes.patch'), bundle.files.map((f) => f.diff).join('\n'), 'utf8');
  }

  await auditSink().append({
    actor: args.actor ?? 'user',
    action: 'fix.approved',
    runId: args.runId,
    tool: 'author',
    input: { fixId: proposal.id, playbookId: proposal.playbookId },
    output: { branch: bundle.branch, dir, files: bundle.files.length },
  });

  return { proposalId: proposal.id, dir, bundle };
}

/** Fix ids already approved for a run, read back from the audit log. */
export async function approvedFixIds(runId: string): Promise<Set<string>> {
  const ids = new Set<string>();
  for (const e of await auditSink().list(runId)) {
    if (e.action !== 'fix.approved') continue;
    const fixId = (e.input as { fixId?: string } | undefined)?.fixId;
    if (fixId) ids.add(fixId);
  }
  return ids;
}
