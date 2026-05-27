import { describe, expect, it } from 'vitest';
import { FindingSchema, makeFindingId, parseFindings, SEVERITY_WEIGHT } from './findings.js';

describe('makeFindingId', () => {
  it('is deterministic for the same inputs', () => {
    const a = makeFindingId('trivy', 'CVE-2024-1', { kind: 'Pod', name: 'web', namespace: 'prod' });
    const b = makeFindingId('trivy', 'CVE-2024-1', { kind: 'Pod', name: 'web', namespace: 'prod' });
    expect(a).toBe(b);
    expect(a.startsWith('trivy:')).toBe(true);
  });

  it('differs when the resource differs', () => {
    const a = makeFindingId('trivy', 'CVE-2024-1', { kind: 'Pod', name: 'web' });
    const b = makeFindingId('trivy', 'CVE-2024-1', { kind: 'Pod', name: 'api' });
    expect(a).not.toBe(b);
  });
});

describe('FindingSchema', () => {
  it('parses a minimal valid finding', () => {
    const f = FindingSchema.parse({
      id: 'trivy:abc',
      source: 'trivy',
      ruleId: 'CVE-2024-1',
      title: 'OpenSSL vuln',
      severity: 'high',
      resource: { kind: 'Pod', name: 'web' },
      raw: {},
    });
    expect(f.description).toBe(''); // default applied
    expect(f.severity).toBe('high');
  });

  it('rejects an invalid severity', () => {
    expect(() =>
      parseFindings([
        {
          id: 'x',
          source: 'trivy',
          ruleId: 'r',
          title: 't',
          severity: 'apocalyptic',
          resource: { kind: 'Pod', name: 'web' },
          raw: {},
        },
      ]),
    ).toThrow();
  });
});

describe('SEVERITY_WEIGHT', () => {
  it('orders critical > high > medium > low > info', () => {
    expect(SEVERITY_WEIGHT.critical).toBeGreaterThan(SEVERITY_WEIGHT.high);
    expect(SEVERITY_WEIGHT.high).toBeGreaterThan(SEVERITY_WEIGHT.medium);
    expect(SEVERITY_WEIGHT.medium).toBeGreaterThan(SEVERITY_WEIGHT.low);
    expect(SEVERITY_WEIGHT.low).toBeGreaterThan(SEVERITY_WEIGHT.info);
  });
});
