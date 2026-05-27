import type { AttackPath, AuditEntry, Finding, ResourceRef } from '@k8s-sentinel/core';
import type { RemediationProposal } from '@k8s-sentinel/agent-author';
import {
  PostureSnapshotSchema,
  type PostureSnapshot,
  type WireAttackPath,
  type WireAuditEntry,
  type WireFinding,
  type WireRemediation,
  type WireRun,
} from '@k8s-sentinel/relay-protocol';
import type { RunRecord } from '../store.js';

/**
 * Map the agent's internal (core) types onto the relay wire contract — the
 * explicit "what leaves the cluster" projection (docs/DATA-BOUNDARY.md). Only
 * the listed fields cross; everything else (raw scanner output, secrets, full
 * manifests) is dropped here by construction, not by trust. The result is
 * validated against the wire schema before it is returned, so a mapping bug
 * fails in-cluster rather than at the relay.
 */

function toWireResource(r: ResourceRef): WireFinding['resource'] {
  return {
    kind: r.kind,
    name: r.name,
    namespace: r.namespace,
    image: r.image,
    path: r.path,
  };
}

function toWireFinding(f: Finding): WireFinding {
  return {
    id: f.id,
    source: f.source,
    ruleId: f.ruleId,
    title: f.title,
    description: f.description,
    severity: f.severity,
    resource: toWireResource(f.resource),
    reachable: f.reachable,
    exploitScore: f.exploitScore,
    attackPathId: f.attackPathId,
    controls: f.controls?.map((c) => ({ framework: c.framework, id: c.id, title: c.title })),
    baseScore: f.baseScore,
  };
}

function toWirePath(p: AttackPath): WireAttackPath {
  return {
    id: p.id,
    narrative: p.narrative,
    score: p.score,
    entryPoint: p.entryPoint,
    steps: p.steps.map((s) => ({
      kind: s.kind,
      resource: toWireResource(s.resource),
      detail: s.detail,
      findingIds: s.findingIds,
    })),
    findingIds: p.findingIds,
  };
}

function toWireRemediation(p: RemediationProposal): WireRemediation {
  return {
    id: p.id,
    playbookId: p.playbookId,
    title: p.title,
    severity: p.severity,
    kind: p.kind,
    rationale: p.rationale,
    path: p.path,
    diff: p.diff,
    manualSteps: p.manualSteps,
    controls: p.controls.map((c) => ({ framework: c.framework, id: c.id, title: c.title })),
    findingIds: p.findingIds,
    attackPathId: p.attackPathId,
    priority: p.priority,
    branch: p.branch,
    prTitle: p.prTitle,
    prBody: p.prBody,
  };
}

function toWireAudit(e: AuditEntry): WireAuditEntry {
  return { seq: e.seq, ts: e.ts, actor: e.actor, agent: e.agent, action: e.action, runId: e.runId };
}

function toWireRun(run: RunRecord): WireRun {
  return {
    id: run.id,
    status: run.status === 'running' || run.status === 'failed' ? run.status : 'complete',
    engine: run.engine,
    usedFixtures: run.usedFixtures,
    findingCount: run.findingCount,
    pathCount: run.pathCount,
    riskScore: run.riskScore,
    summary: run.summary,
    startedAt: run.createdAt,
    finishedAt: run.status === 'running' ? null : new Date().toISOString(),
  };
}

export interface SnapshotInput {
  run: RunRecord;
  findings: Finding[];
  paths: AttackPath[];
  proposals: RemediationProposal[];
  audit: AuditEntry[];
}

/** Build + validate the posture snapshot pushed up the tunnel. */
export function toPostureSnapshot(input: SnapshotInput): PostureSnapshot {
  const snapshot: PostureSnapshot = {
    run: toWireRun(input.run),
    findings: input.findings.map(toWireFinding),
    paths: input.paths.map(toWirePath),
    remediations: input.proposals.map(toWireRemediation),
    audit: input.audit.map(toWireAudit),
  };
  // Validate at the source: a mapping/limit violation throws here, in-cluster.
  return PostureSnapshotSchema.parse(snapshot);
}
