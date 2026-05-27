import { describe, expect, it } from 'vitest';
import type { AttackPath, AuditEntry, Finding } from '@k8s-sentinel/core';
import type { RemediationProposal } from '@k8s-sentinel/agent-author';
import { PostureSnapshotSchema } from '@k8s-sentinel/relay-protocol';
import type { RunRecord } from '../store.js';
import { toPostureSnapshot } from './wire.js';

const run: RunRecord = {
  id: 'run-1',
  createdAt: '2026-05-27T00:00:00.000Z',
  status: 'complete',
  engine: 'claude',
  usedFixtures: true,
  findingCount: 1,
  pathCount: 1,
  riskScore: 72,
  summary: 'one reachable critical on payment-api',
};

const finding: Finding = {
  id: 'f1',
  source: 'trivy',
  ruleId: 'CVE-2024-0001',
  title: 'critical RCE',
  severity: 'critical',
  resource: { kind: 'Deployment', name: 'payment-api', namespace: 'prod', image: 'pay:1.0' },
  reachable: true,
  exploitScore: 91,
  attackPathId: 'p1',
  controls: [{ framework: 'CIS', id: '5.2.1', title: 'minimize containers' }],
  baseScore: 9.8,
};

const path: AttackPath = {
  id: 'p1',
  narrative: 'exposed → running → vulnerable',
  score: 88,
  entryPoint: 'internet',
  steps: [
    {
      kind: 'exposed',
      resource: { kind: 'Service', name: 'payment-api', namespace: 'prod' },
      detail: 'LoadBalancer',
      findingIds: ['f1'],
    },
  ],
  findingIds: ['f1'],
};

const proposal = {
  id: 'fix-1',
  playbookId: 'pin-image',
  title: 'Pin image',
  severity: 'critical',
  kind: 'patch',
  rationale: 'use a digest',
  path: 'deploy/payment.yaml',
  diff: '--- a\n+++ b\n',
  manualSteps: [],
  controls: [{ framework: 'CIS', id: '5.2.1' }],
  findingIds: ['f1'],
  attackPathId: 'p1',
  priority: 99,
  status: 'proposed',
  branch: 'sentinel/pin-image',
  prTitle: '[K8s Sentinel] Pin image',
  prBody: 'body',
} satisfies RemediationProposal;

const audit: AuditEntry[] = [
  {
    seq: 0,
    ts: '2026-05-27T00:00:00.000Z',
    actor: 'orchestrator',
    action: 'scan.start',
    runId: 'run-1',
    prevHash: '',
    hash: 'abc',
  },
];

describe('toPostureSnapshot', () => {
  it('projects core types onto the validated wire contract', () => {
    const snap = toPostureSnapshot({ run, findings: [finding], paths: [path], proposals: [proposal], audit });

    expect(PostureSnapshotSchema.safeParse(snap).success).toBe(true);
    expect(snap.run).toMatchObject({ id: 'run-1', status: 'complete', startedAt: run.createdAt });
    expect(snap.run.finishedAt).toBeTruthy();
    expect(snap.findings[0]).toMatchObject({ id: 'f1', exploitScore: 91, attackPathId: 'p1' });
    expect(snap.paths[0]?.steps[0]?.kind).toBe('exposed');
    expect(snap.remediations[0]).toMatchObject({ id: 'fix-1', branch: 'sentinel/pin-image' });
    // Audit is projected to the minimal display fields — hash/prevHash do NOT cross.
    expect(snap.audit[0]).toEqual({
      seq: 0,
      ts: '2026-05-27T00:00:00.000Z',
      actor: 'orchestrator',
      action: 'scan.start',
      runId: 'run-1',
    });
    expect('hash' in snap.audit[0]!).toBe(false);
  });

  it('marks a still-running run with a null finishedAt', () => {
    const snap = toPostureSnapshot({
      run: { ...run, status: 'running' },
      findings: [],
      paths: [],
      proposals: [],
      audit: [],
    });
    expect(snap.run.status).toBe('running');
    expect(snap.run.finishedAt).toBeNull();
  });
});
