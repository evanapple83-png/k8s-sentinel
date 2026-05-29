import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  chartOciRef,
  chartRef,
  chartVersion,
  clearChartVerifyCache,
  isHelmManifest,
  parseOciRef,
  verifyChartPublished,
} from './chart';

/**
 * Pure config + the GHCR publication probe.
 *
 * The probe's value isn't the happy path — it's the two refusals that keep a
 * broken `helm install` off the Connect screen:
 *   - 404 at the tag           → not-published
 *   - a container image is     → not-a-chart  (the historical trap: the agent
 *     parked at the chart path    image and the chart share `…/k8s-sentinel`)
 */

const HELM = 'application/vnd.cncf.helm.config.v1+json';
const IMAGE = 'application/vnd.oci.image.config.v1+json';

describe('parseOciRef', () => {
  it('splits registry from repository, scheme-tolerant', () => {
    expect(parseOciRef('ghcr.io/acme/k8s-sentinel')).toEqual({
      registry: 'ghcr.io',
      repository: 'acme/k8s-sentinel',
    });
    expect(parseOciRef('oci://ghcr.io/acme/nested/chart')).toEqual({
      registry: 'ghcr.io',
      repository: 'acme/nested/chart',
    });
  });
});

describe('isHelmManifest', () => {
  it('accepts only the Helm config mediaType', () => {
    expect(isHelmManifest({ config: { mediaType: HELM } })).toBe(true);
    expect(isHelmManifest({ config: { mediaType: IMAGE } })).toBe(false);
    expect(isHelmManifest(null)).toBe(false);
    expect(isHelmManifest({})).toBe(false);
  });
});

describe('chart config', () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
  });

  it('defaults to the repo GHCR org and strips an accidental oci:// prefix', () => {
    delete process.env.SENTINEL_CHART_REF;
    expect(chartRef()).toBe('ghcr.io/evanapple83-png/k8s-sentinel');
    process.env.SENTINEL_CHART_REF = 'oci://ghcr.io/acme/k8s-sentinel';
    expect(chartRef()).toBe('ghcr.io/acme/k8s-sentinel');
    expect(chartOciRef()).toBe('oci://ghcr.io/acme/k8s-sentinel');
  });

  it('reads the version override', () => {
    process.env.SENTINEL_CHART_VERSION = '1.2.3';
    expect(chartVersion()).toBe('1.2.3');
  });
});

describe('verifyChartPublished', () => {
  const saved = { ...process.env };

  beforeEach(() => {
    clearChartVerifyCache();
    process.env.SENTINEL_CHART_REF = 'ghcr.io/acme/k8s-sentinel';
    process.env.SENTINEL_CHART_VERSION = '0.2.0';
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    process.env = { ...saved };
  });

  function stubFetch(manifest: { status: number; mediaType?: string }) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.includes('/token')) {
          return new Response(JSON.stringify({ token: 't' }), { status: 200 });
        }
        if (manifest.status === 404) return new Response('not found', { status: 404 });
        return new Response(JSON.stringify({ config: { mediaType: manifest.mediaType } }), {
          status: manifest.status,
        });
      }),
    );
  }

  it('confirms a real Helm chart', async () => {
    stubFetch({ status: 200, mediaType: HELM });
    expect(await verifyChartPublished()).toEqual({ ok: true });
  });

  it('flags a 404 as not-published', async () => {
    stubFetch({ status: 404 });
    expect(await verifyChartPublished()).toMatchObject({ ok: false, reason: 'not-published' });
  });

  it('flags a container image as not-a-chart', async () => {
    stubFetch({ status: 200, mediaType: IMAGE });
    expect(await verifyChartPublished()).toMatchObject({ ok: false, reason: 'not-a-chart' });
  });

  it('skips verification for non-ghcr registries', async () => {
    process.env.SENTINEL_CHART_REF = 'registry.example.com/acme/chart';
    const f = vi.fn();
    vi.stubGlobal('fetch', f);
    expect(await verifyChartPublished()).toEqual({ ok: true });
    expect(f).not.toHaveBeenCalled();
  });

  it('memoizes within the TTL', async () => {
    stubFetch({ status: 200, mediaType: HELM });
    await verifyChartPublished();
    await verifyChartPublished();
    // token + manifest = 2 calls for the first probe; the second is cached.
    expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length).toBe(2);
  });
});
