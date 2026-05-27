import { z } from 'zod';

/**
 * Common findings schema (SARIF-inspired).
 *
 * Every scanner (Trivy, Kubescape, kube-bench, Falco) emits a different shape.
 * The Collector normalizes all of them into `Finding[]` so the Analyst can
 * reason over one model. We keep the original tool payload in `raw` (untrusted)
 * and only ever surface sanitized text to agents.
 */

export const SCANNER_SOURCES = ['trivy', 'kubescape', 'kube-bench', 'falco'] as const;
export type ScannerSource = (typeof SCANNER_SOURCES)[number];

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Ordinal weight for sorting/aggregation. Higher = worse. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 70,
  medium: 40,
  low: 15,
  info: 0,
};

/** A reference to the Kubernetes resource a finding is about. */
export const ResourceRefSchema = z.object({
  namespace: z.string().optional(),
  kind: z.string(), // Pod, Deployment, Node, Role, Service, ClusterRole, ...
  name: z.string(),
  /** Container image (when the finding is image/vuln scoped). */
  image: z.string().optional(),
  /** Free-form locator, e.g. a container name or a manifest path. */
  path: z.string().optional(),
  /** API group/version, when known (e.g. "apps/v1"). */
  apiVersion: z.string().optional(),
});
export type ResourceRef = z.infer<typeof ResourceRefSchema>;

/** Compliance control identifiers a finding maps to (set by the Analyst). */
export const ControlRefSchema = z.object({
  framework: z.enum(['CIS', 'NSA-CISA', 'SOC2', 'MITRE-ATTACK', 'PCI-DSS']),
  id: z.string(), // e.g. "CIS-5.2.5", "NSA-CISA-PodSecurity", "SOC2-CC6.1"
  title: z.string().optional(),
});
export type ControlRef = z.infer<typeof ControlRefSchema>;

export const FindingSchema = z.object({
  /** Stable id derived from (source, ruleId, resource) — see makeFindingId. */
  id: z.string(),
  source: z.enum(SCANNER_SOURCES),
  /** Scanner-native rule/check identifier, e.g. CVE-2024-1234, "C-0001". */
  ruleId: z.string(),
  title: z.string(),
  description: z.string().default(''),
  severity: z.enum(SEVERITIES),
  resource: ResourceRefSchema,
  /** Original, untrusted tool output. Never feed directly to an agent. */
  raw: z.unknown(),

  // ---- Enriched by the Analyst (Phase 2) ------------------------------------
  /** Is the affected resource actually running and exposed? */
  reachable: z.boolean().optional(),
  /** 0–100, reachability-weighted exploitability (NOT raw CVSS). */
  exploitScore: z.number().min(0).max(100).optional(),
  /** Links the finding into a correlated attack path. */
  attackPathId: z.string().optional(),
  /** CIS / NSA-CISA / SOC2 / ... control mappings. */
  controls: z.array(ControlRefSchema).optional(),
  /** Raw upstream score for reference/audit (e.g. CVSS base). */
  baseScore: z.number().optional(),

  /** When the finding was observed. */
  observedAt: z.string().datetime().optional(),
});
export type Finding = z.infer<typeof FindingSchema>;

/**
 * Deterministic, collision-resistant finding id. Stable across scans so the
 * UI can show "what changed since last scan" and audit can dedupe.
 */
export function makeFindingId(
  source: ScannerSource,
  ruleId: string,
  resource: ResourceRef,
): string {
  const key = [
    source,
    ruleId,
    resource.namespace ?? '-',
    resource.kind,
    resource.name,
    resource.image ?? '-',
    resource.path ?? '-',
  ]
    .join('/')
    .toLowerCase();
  return `${source}:${fnv1a(key)}`;
}

/** Small, dependency-free 32-bit hash (FNV-1a) rendered as hex. */
export function fnv1a(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/** Validate + coerce an array of findings (defensive: scanners drift). */
export function parseFindings(input: unknown): Finding[] {
  return z.array(FindingSchema).parse(input);
}
