import { describe, expect, it } from 'vitest';
import { ClusterInventorySchema, FindingSchema } from '@k8s-sentinel/core';
import { runCollector } from './collector.js';
import { fixtureInventory } from './inventory-fixture.js';

describe('runCollector (offline / fixtures)', () => {
  it('produces a normalized findings set from all four scanners', async () => {
    const out = await runCollector();
    const sources = new Set(out.findings.map((f) => f.source));
    expect(sources).toEqual(new Set(['trivy', 'kubescape', 'kube-bench', 'falco']));
    expect(out.stats.usedFixtures).toBe(true);
    expect(out.stats.totalFindings).toBe(out.findings.length);
    for (const f of out.findings) expect(() => FindingSchema.parse(f)).not.toThrow();
  });

  it('returns a schema-valid inventory with the exposed, privileged payment-api', async () => {
    const out = await runCollector();
    expect(() => ClusterInventorySchema.parse(out.inventory)).not.toThrow();
    const pay = out.inventory.workloads.find((w) => w.name === 'payment-api');
    expect(pay).toMatchObject({ privileged: true, runAsRoot: true, serviceAccount: 'payment-sa' });
    const svc = out.inventory.services.find((s) => s.name === 'payment-api-svc');
    expect(svc?.exposed).toBe(true);
  });

  it('de-duplicates findings by id', async () => {
    const out = await runCollector();
    const ids = out.findings.map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('fixtureInventory', () => {
  it('models payment-sa as a secret-reading cluster-admin', () => {
    const inv = fixtureInventory();
    const sa = inv.rbac.find((r) => r.serviceAccount === 'payment-sa');
    expect(sa).toMatchObject({ canReadSecrets: true, clusterAdmin: true });
  });
});
