/**
 * Single source of truth for the published Helm chart the Connect screen tells
 * operators to `helm install`.
 *
 * The OCI path used to be the literal placeholder `ghcr.io/your-org/k8s-sentinel`
 * sprinkled across three command builders. That is now derived from ONE config
 * value (`SENTINEL_CHART_REF`) so the real publishing path is set in exactly one
 * place — env in prod, the default here for local/dev.
 *
 * It also knows how to *verify* that a Helm chart actually exists at that path
 * (GHCR speaks the OCI distribution API), so the UI can refuse to hand out a
 * copy-paste command that would fail with a registry 404 or — subtler — point
 * at a container image that happens to share the repo path but is NOT a chart.
 */

/** OCI config mediaType that distinguishes a Helm chart from a container image. */
const HELM_CONFIG_MEDIA_TYPE = 'application/vnd.cncf.helm.config.v1+json';

/**
 * The chart repo path WITHOUT the `oci://` scheme, e.g.
 * `ghcr.io/evanapple83-png/k8s-sentinel`. Defaults to the repo's real GHCR org
 * (see deploy/helm/Chart.yaml `home:` + .github/workflows/publish-images.yml).
 */
export function chartRef(): string {
  return (process.env.SENTINEL_CHART_REF ?? 'ghcr.io/evanapple83-png/k8s-sentinel').replace(
    /^oci:\/\//,
    '',
  );
}

/** The chart version/tag installed and verified. Matches deploy/helm/Chart.yaml. */
export function chartVersion(): string {
  return process.env.SENTINEL_CHART_VERSION ?? '0.2.0';
}

/** The full `oci://…` reference used verbatim in the `helm install` command. */
export function chartOciRef(): string {
  return `oci://${chartRef()}`;
}

// --- Publication verification ----------------------------------------------

export type ChartVerifyResult =
  | { ok: true }
  | { ok: false; reason: 'not-published' | 'not-a-chart' | 'unreachable'; detail?: string };

/** Split `ghcr.io/owner/name` → `{ registry, repository }`. */
export function parseOciRef(ref: string): { registry: string; repository: string } {
  const clean = ref.replace(/^oci:\/\//, '');
  const slash = clean.indexOf('/');
  if (slash === -1) return { registry: clean, repository: '' };
  return { registry: clean.slice(0, slash), repository: clean.slice(slash + 1) };
}

/** True only for a manifest whose config marks it as a Helm chart artifact. */
export function isHelmManifest(manifest: unknown): boolean {
  const mt = (manifest as { config?: { mediaType?: unknown } } | null)?.config?.mediaType;
  return mt === HELM_CONFIG_MEDIA_TYPE;
}

// Cache the verdict briefly so the every-3s Connect polling + Regenerate clicks
// don't hammer the registry. Keyed by the exact ref:version we checked.
let cached: { key: string; at: number; result: ChartVerifyResult } | null = null;
const CACHE_TTL_MS = 60_000;

/**
 * Confirm a Helm chart is actually published at the configured ref+version.
 *
 * Only GHCR is verified over the wire (the default + overwhelmingly common
 * target). For any other registry we can't assume an API shape, so we don't
 * block — the operator chose a custom `SENTINEL_CHART_REF` and owns it.
 *
 * Failure modes the UI cares about:
 *   - not-published : registry returned 404 for the tag → nothing there
 *   - not-a-chart   : something is there, but it's a container image, not a
 *                     Helm chart (the historical trap: the agent *image* and the
 *                     chart would share `…/k8s-sentinel`)
 *   - unreachable   : couldn't reach the registry / timed out → can't confirm
 */
export async function verifyChartPublished(now = Date.now): Promise<ChartVerifyResult> {
  const ref = chartRef();
  const version = chartVersion();
  const key = `${ref}@${version}`;
  const ts = now();

  if (cached && cached.key === key && ts - cached.at < CACHE_TTL_MS) return cached.result;

  const result = await probe(ref, version);
  cached = { key, at: ts, result };
  return result;
}

/** Clear the memoized verdict (tests + after a known publish). */
export function clearChartVerifyCache(): void {
  cached = null;
}

async function probe(ref: string, version: string): Promise<ChartVerifyResult> {
  const { registry, repository } = parseOciRef(ref);
  if (registry !== 'ghcr.io' || !repository) return { ok: true };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    // GHCR requires a bearer token even for public reads; the token endpoint
    // grants pull scope anonymously.
    const tokRes = await fetch(
      `https://ghcr.io/token?service=ghcr.io&scope=repository:${repository}:pull`,
      { signal: controller.signal },
    );
    if (!tokRes.ok) return { ok: false, reason: 'unreachable', detail: `token ${tokRes.status}` };
    const token = ((await tokRes.json()) as { token?: string }).token;
    if (!token) return { ok: false, reason: 'unreachable', detail: 'no token' };

    const manRes = await fetch(`https://ghcr.io/v2/${repository}/manifests/${version}`, {
      headers: {
        authorization: `Bearer ${token}`,
        accept:
          'application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json',
      },
      signal: controller.signal,
    });

    if (manRes.status === 404) return { ok: false, reason: 'not-published' };
    if (!manRes.ok) return { ok: false, reason: 'unreachable', detail: `manifest ${manRes.status}` };

    const manifest = (await manRes.json()) as unknown;
    if (isHelmManifest(manifest)) return { ok: true };
    return {
      ok: false,
      reason: 'not-a-chart',
      detail:
        (manifest as { config?: { mediaType?: string } })?.config?.mediaType ?? 'unknown mediaType',
    };
  } catch {
    return { ok: false, reason: 'unreachable', detail: 'fetch failed' };
  } finally {
    clearTimeout(timeout);
  }
}
