import { describe, expect, it } from 'vitest';
import { AttackPathSchema, FindingSchema } from '@k8s-sentinel/core';
import { runCollector } from '@k8s-sentinel/agent-collector';
import { runAnalyst } from './analyze.js';
import { answerQuery, parseQuery } from './query.js';

/**
 * End-to-end against the offline fixtures: an internet-exposed, privileged,
 * root, secret-reading `payment-api` in `prod` (the raw material for a real
 * external-to-secret attack path) vs. a dormant `batch-cleaner` in `default`.
 */
async function analysed() {
  const collector = await runCollector();
  const out = runAnalyst({ findings: collector.findings, inventory: collector.inventory });
  return { collector, out };
}

describe('runAnalyst — reachability ranking (DoD: reranked by reachability)', () => {
  it('ranks a reachable finding above a dormant one of equal severity', async () => {
    const { out } = await analysed();
    const reachable = out.findings.find((f) => f.reachable === true && f.severity === 'critical');
    const dormant = out.findings.find((f) => f.reachable === false);
    expect(reachable?.exploitScore).toBeGreaterThan(0);
    if (dormant) {
      // A dormant workload's finding is discounted (×0.25 in scoreFinding).
      expect(reachable!.exploitScore!).toBeGreaterThan(dormant.exploitScore ?? 0);
    }
  });

  it('returns findings sorted by exploitScore, not CVSS/severity', async () => {
    const { out } = await analysed();
    for (let i = 1; i < out.findings.length; i++) {
      expect(out.findings[i - 1]!.exploitScore ?? 0).toBeGreaterThanOrEqual(
        out.findings[i]!.exploitScore ?? 0,
      );
    }
  });

  it('every finding stays schema-valid and is mapped to ≥1 compliance control', async () => {
    const { out } = await analysed();
    for (const f of out.findings) {
      expect(() => FindingSchema.parse(f)).not.toThrow();
      expect(f.controls?.length ?? 0).toBeGreaterThan(0);
    }
    // CIS, NSA-CISA, SOC2 and MITRE all represented across the run.
    expect(Object.keys(out.stats.compliance).length).toBeGreaterThanOrEqual(3);
  });
});

describe('runAnalyst — correlation (core IP)', () => {
  it('builds a payment-api attack path and stamps its findings', async () => {
    const { out } = await analysed();
    expect(out.paths.length).toBeGreaterThan(0);
    for (const p of out.paths) expect(() => AttackPathSchema.parse(p)).not.toThrow();

    const top = out.paths[0]!;
    expect(top.entryPoint).toBe('internet');
    const kinds = top.steps.map((s) => s.kind);
    expect(kinds).toContain('exposed');
    expect(kinds).toContain('running');
    expect(kinds).toContain('over-privileged');
    expect(kinds).toContain('secret-access'); // full external-to-secret chain

    // Every finding in the path is stamped with the path id.
    for (const fid of top.findingIds) {
      const f = out.findings.find((x) => x.id === fid)!;
      expect(f.attackPathId).toBe(top.id);
    }
  });

  it('does NOT build a path for the dormant batch-cleaner (not running)', async () => {
    const { out } = await analysed();
    const mentionsCleaner = out.paths.some((p) =>
      p.steps.some((s) => s.resource.name === 'batch-cleaner'),
    );
    expect(mentionsCleaner).toBe(false);
  });

  it('produces a posture risk score and a non-empty summary', async () => {
    const { out } = await analysed();
    expect(out.riskScore).toBeGreaterThan(0);
    expect(out.riskScore).toBeLessThanOrEqual(100);
    expect(out.summary).toMatch(/attack path/);
  });
});

describe('answerQuery — plain-English (DoD example)', () => {
  it('"show everything internet-exposed running as root" returns only payment-api', async () => {
    const { out } = await analysed();
    const res = answerQuery('show everything internet-exposed running as root', {
      findings: out.findings,
      paths: out.paths,
      contexts: out.contexts,
      namespaces: out.namespaces,
    });

    expect(res.parsed.facets.map((f) => f.key)).toEqual(
      expect.arrayContaining(['internet-exposed', 'run-as-root']),
    );
    expect(res.findings.length).toBeGreaterThan(0);
    // Every hit must be on the internet-exposed, root payment-api in prod.
    for (const f of res.findings) {
      const ctx = out.contexts.get(f.id)!;
      expect(ctx.internetExposed).toBe(true);
      expect(ctx.runAsRoot).toBe(true);
      expect(ctx.workload?.name).toBe('payment-api');
    }
    // frontend is exposed-but-not-root → excluded.
    expect(res.findings.every((f) => f.resource.name !== 'frontend')).toBe(true);
    // The matching findings surface their attack path.
    expect(res.paths.length).toBeGreaterThan(0);
  });

  it('filters by severity and namespace', async () => {
    const { out } = await analysed();
    const res = answerQuery('critical findings in prod', {
      findings: out.findings,
      paths: out.paths,
      contexts: out.contexts,
      namespaces: out.namespaces,
    });
    expect(res.parsed.severities).toEqual(['critical']);
    expect(res.parsed.namespace).toBe('prod');
    for (const f of res.findings) {
      expect(f.severity).toBe('critical');
      // Namespace is resolved via the attributed workload, so an image-scoped
      // Trivy CVE (resource.namespace = undefined) still counts as "in prod".
      const ns = out.contexts.get(f.id)?.workload?.namespace ?? f.resource.namespace;
      expect(ns).toBe('prod');
    }
  });

  it('"can read secrets" matches the secret-reaching workload', async () => {
    const { out } = await analysed();
    const res = answerQuery('what can read secrets', {
      findings: out.findings,
      paths: out.paths,
      contexts: out.contexts,
      namespaces: out.namespaces,
    });
    expect(res.findings.length).toBeGreaterThan(0);
    for (const f of res.findings) expect(out.contexts.get(f.id)?.canReachSecret).toBe(true);
  });

  it('a no-filter query returns everything, exploit-ranked', async () => {
    const { out } = await analysed();
    const res = answerQuery('show me everything', {
      findings: out.findings,
      paths: out.paths,
      contexts: out.contexts,
      namespaces: out.namespaces,
    });
    expect(res.findings.length).toBe(out.findings.length);
    expect(res.answer).toMatch(/ranked by exploitability/);
  });

  it('respects "top N"', async () => {
    const { out } = await analysed();
    const res = answerQuery('top 3 findings', {
      findings: out.findings,
      paths: out.paths,
      contexts: out.contexts,
      namespaces: out.namespaces,
    });
    expect(res.parsed.topN).toBe(3);
    expect(res.findings.length).toBeLessThanOrEqual(3);
  });
});

describe('parseQuery — consumption order', () => {
  it('does not let "internet-exposed" leak into the bare "exposed" facet twice', () => {
    const p = parseQuery('internet-exposed workloads');
    const keys = p.facets.map((f) => f.key);
    expect(keys).toContain('internet-exposed');
    expect(keys).not.toContain('exposed');
  });

  it('treats "running as root" as run-as-root, not a separate running facet', () => {
    const p = parseQuery('running as root');
    const keys = p.facets.map((f) => f.key);
    expect(keys).toEqual(['run-as-root']);
  });

  it('keeps "over-privileged" distinct from "privileged"', () => {
    const p = parseQuery('over-privileged');
    expect(p.facets.map((f) => f.key)).toEqual(['over-privileged']);
  });
});
