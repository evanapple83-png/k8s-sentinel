import { describe, expect, it } from 'vitest';
import { PostureSnapshotSchema } from './wire';
import {
  clamp01,
  isConfidence,
  isExposure,
  isSsvc,
  mapToPostureSnapshot,
  type ArgusReportJson,
} from './argus-mapper';

/**
 * Mapper tests — pure projection from raw ARGUS v3 JSON onto the wire
 * PostureSnapshot. These lock the contract between Python and TS, so any
 * drift here will surface as a failing test before it hits the dashboard.
 *
 * The mapper is the inlined sibling of apps/api/src/tunnel/argus.ts; the
 * tests below intentionally hit the same surface that file's smoke fixture
 * covers, scaled down to the small handful of fields the wire schema actually
 * stores.
 */

describe('type guards', () => {
  it('isSsvc accepts only the four canonical decisions', () => {
    expect(isSsvc('Act')).toBe(true);
    expect(isSsvc('Attend')).toBe(true);
    expect(isSsvc('Track')).toBe(true);
    expect(isSsvc('Track*')).toBe(true);
    expect(isSsvc('act')).toBe(false);
    expect(isSsvc(undefined)).toBe(false);
  });
  it('isConfidence accepts high/medium/n/a', () => {
    expect(isConfidence('high')).toBe(true);
    expect(isConfidence('n/a')).toBe(true);
    expect(isConfidence('low')).toBe(false);
  });
  it('isExposure accepts the four bands', () => {
    expect(isExposure('open')).toBe(true);
    expect(isExposure('cluster')).toBe(true);
    expect(isExposure('exposed')).toBe(false);
  });
  it('clamp01 squeezes EPSS into [0, 1]', () => {
    expect(clamp01(-0.5)).toBe(0);
    expect(clamp01(0.7)).toBe(0.7);
    expect(clamp01(2)).toBe(1);
  });
});

describe('mapToPostureSnapshot', () => {
  it('maps an empty report into a valid (if empty) snapshot', () => {
    const out = mapToPostureSnapshot({});
    expect(out.findings).toEqual([]);
    expect(out.paths).toEqual([]);
    expect(out.remediations).toEqual([]);
    expect(out.audit).toEqual([]);
    expect(out.run.engine).toBe('argus-v3');
    expect(PostureSnapshotSchema.safeParse(out).success).toBe(true);
  });

  it('projects a small report into wire shapes that pass the schema', () => {
    const report: ArgusReportJson = {
      cluster: 'test-cluster',
      scannedAt: '2026-05-28T12:00:00Z',
      riskScore: 73,
      intel: { kev_count: 12, version: '2026.05.28', source: 'cisa' },
      reachableJewels: ['secret:kube-system/admin'],
      paths: {
        'secret:kube-system/admin': [
          ['ext:internet', 'wl:default/web', 'ingress', null, false],
          ['wl:default/web', 'sa:default/web-sa', 'uses', null, false],
          ['sa:default/web-sa', 'secret:kube-system/admin', 'reads', null, true],
        ],
      },
      chokePoints: [
        { control: { type: 'rbac-least-privilege', sa: 'default/web-sa', what: 'list secrets' }, breaks: 1, targets: ['secret:kube-system/admin'] },
      ],
      findings: [
        {
          id: 'f-1',
          cve: 'CVE-2025-9999',
          title: 'Exposed kubelet',
          target: 'default/web',
          kev: true,
          ransomware: false,
          epss: 0.83,
          cvss: 9.1,
          exposure: 'open',
          confidence: 'high',
          decision: 'Act',
          score: 95,
          reaches: ['secret:kube-system/admin'],
        },
      ],
      workloads: [{ id: 'default/web', kind: 'Deployment', namespace: 'default', image: 'nginx:1.25' }],
      activeFindings: [
        { id: 'f-1', source: 'trivy', ruleId: 'CVE-2025-9999', severity: 'critical', title: 'Exposed kubelet' },
      ],
    };
    const out = mapToPostureSnapshot(report);

    // Wire schema is the trust boundary; if this fails the API would 422.
    const parsed = PostureSnapshotSchema.safeParse(out);
    expect(parsed.success).toBe(true);

    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]).toMatchObject({
      cve: 'CVE-2025-9999',
      kev: true,
      ssvc: 'Act',
      confidence: 'high',
      exposure: 'open',
      severity: 'critical', // Act → critical
    });
    expect(out.paths).toHaveLength(1);
    expect(out.paths[0]?.steps).toHaveLength(3);
    expect(out.chokePoints?.[0]?.breaks).toBe(1);
    expect(out.chokePoints?.[0]?.totalPaths).toBe(1);
    expect(out.intel).toMatchObject({ source: 'cisa', kevCount: 12, version: '2026.05.28' });
  });

  it('omits chokePoints + intel when the report has neither', () => {
    const out = mapToPostureSnapshot({ findings: [], paths: {} });
    expect(out.chokePoints).toBeUndefined();
    expect(out.intel).toBeUndefined();
  });

  it('surfaces non-CVE activeFindings (kube-bench / kubescape) the engine drops (F15)', () => {
    const report: ArgusReportJson = {
      // engine's CVE-correlated set
      findings: [{ id: 'trivy-001', cve: 'CVE-2026-1', title: 'rce', target: 'cluster', decision: 'Act', score: 90 }],
      // raw scanner findings — includes the CVE (already scored) + non-CVE rows
      activeFindings: [
        { id: 'trivy-001', source: 'trivy', type: 'cve', cve: 'CVE-2026-1', severity: 'critical', target: 'cluster', title: 'rce' },
        { id: 'kb-001', source: 'kube-bench', type: 'cis', ruleId: '1.2.16', severity: 'medium', target: 'cluster', title: 'anonymous-auth must be false' },
        { id: 'ks-001', source: 'kubescape', type: 'misconfig', ruleId: 'C-0017', severity: 'high', target: 'payments/invoice-api', title: 'immutable container filesystem' },
      ],
      paths: {},
    };
    const out = mapToPostureSnapshot(report);
    const bySource = out.findings.reduce<Record<string, number>>((a, f) => ((a[f.source] = (a[f.source] ?? 0) + 1), a), {});
    expect(bySource).toEqual({ trivy: 1, 'kube-bench': 1, kubescape: 1 });
    // run.findingCount reflects ALL findings, not just the CVE-correlated set (F17)
    expect(out.run.findingCount).toBe(3);
    const kb = out.findings.find((f) => f.id === 'kb-001')!;
    expect(kb.severity).toBe('medium');
    expect(kb.reachable).toBe(false);
    expect(kb.ruleId).toBe('1.2.16');
    // the already-scored CVE is not duplicated from activeFindings
    expect(out.findings.filter((f) => f.id === 'trivy-001')).toHaveLength(1);
    expect(PostureSnapshotSchema.safeParse(out).success).toBe(true);
  });
});
