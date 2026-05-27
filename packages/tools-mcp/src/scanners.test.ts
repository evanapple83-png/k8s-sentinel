import { describe, expect, it } from 'vitest';
import { FindingSchema } from '@k8s-sentinel/core';
import { allScanners, runAllScanners } from './index.js';
import { TrivyScanner } from './trivy.js';
import { KubescapeScanner } from './kubescape.js';
import { KubeBenchScanner } from './kube-bench.js';
import { FalcoScanner } from './falco.js';

describe('each scanner normalizes its fixture into valid findings', () => {
  it.each(allScanners())('$source produces schema-valid findings', async (scanner) => {
    const result = await scanner.run({});
    expect(result.usedFixture).toBe(true); // no binaries on this host
    expect(result.findings.length).toBeGreaterThan(0);
    for (const f of result.findings) {
      expect(() => FindingSchema.parse(f)).not.toThrow();
      expect(f.source).toBe(scanner.source);
    }
  });
});

describe('Trivy normalization', () => {
  it('extracts the critical OpenSSL CVE on payment-api with a CVSS base score', async () => {
    const { findings } = await new TrivyScanner().run({});
    const cve = findings.find((f) => f.ruleId === 'CVE-2023-0286');
    expect(cve).toBeDefined();
    expect(cve!.severity).toBe('critical');
    expect(cve!.resource.image).toContain('payment-api');
    expect(cve!.baseScore).toBe(7.4);
  });
});

describe('Kubescape normalization', () => {
  it('only emits failed controls and links them to the right resource', async () => {
    const { findings } = await new KubescapeScanner().run({});
    const priv = findings.find((f) => f.ruleId === 'C-0057');
    expect(priv).toBeDefined();
    expect(priv!.severity).toBe('high');
    expect(priv!.resource).toMatchObject({ kind: 'Deployment', name: 'payment-api', namespace: 'prod' });
  });
});

describe('kube-bench normalization', () => {
  it('maps FAIL→high and WARN→medium, skipping PASS', async () => {
    const { findings } = await new KubeBenchScanner().run({});
    const fail = findings.find((f) => f.ruleId === '1.2.1');
    const warn = findings.find((f) => f.ruleId === '1.2.6');
    expect(fail!.severity).toBe('high');
    expect(warn!.severity).toBe('medium');
  });
});

describe('Falco normalization', () => {
  it('maps priority to severity and pulls k8s pod/namespace from output_fields', async () => {
    const { findings } = await new FalcoScanner().run({});
    const crit = findings.find((f) => f.ruleId === 'Read sensitive file untrusted');
    expect(crit!.severity).toBe('critical');
    expect(crit!.resource.namespace).toBe('prod');
    expect(crit!.observedAt).toBeDefined();
  });
});

describe('runAllScanners', () => {
  it('runs all four in parallel and merges findings', async () => {
    const { findings, results } = await runAllScanners();
    expect(results).toHaveLength(4);
    const sources = new Set(findings.map((f) => f.source));
    expect(sources).toEqual(new Set(['trivy', 'kubescape', 'kube-bench', 'falco']));
  });

  it('isolates a crashing scanner without aborting the rest', async () => {
    const boom = {
      source: 'trivy' as const,
      binary: 'x',
      isAvailable: async () => false,
      run: async () => {
        throw new Error('boom');
      },
      normalize: () => [],
    };
    const { results } = await runAllScanners({}, [boom, new FalcoScanner()]);
    expect(results.find((r) => r.warning?.includes('crashed'))).toBeDefined();
    expect(results.find((r) => r.source === 'falco')!.findings.length).toBeGreaterThan(0);
  });
});
