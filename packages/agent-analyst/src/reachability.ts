import type {
  ClusterInventory,
  Finding,
  ResourceRef,
  ServiceInfo,
  Severity,
  WorkloadInfo,
} from '@k8s-sentinel/core';

/**
 * Reachability analysis — the step that turns a raw finding into a *reachable*
 * one (BUILD.md §3, Agent 2). We answer, per finding: is the affected resource
 * actually running, internet-exposed, over-privileged, and can it reach a
 * secret? Those facts drive `exploitScore` (reachability-weighted, NOT raw
 * CVSS) and the correlation engine downstream.
 *
 * Pure and deterministic — like the Collector, the heavy lifting here is code,
 * so the whole Analyst runs offline against fixtures with no model in the loop.
 */

/** Per-finding context derived from the cluster inventory. Drives ranking + NL query. */
export interface FindingContext {
  findingId: string;
  /** The workload the finding was attributed to, if any. */
  workload?: { namespace?: string; kind: string; name: string };
  /** Finding matched to a concrete workload (vs. node/cluster-level). */
  linked: boolean;
  /** Workload is scheduled and has ≥1 replica. */
  running: boolean;
  /** Reachable via at least one exposed Service (NodePort/LB/Ingress) or namespace. */
  exposed: boolean;
  /** Reachable from outside the cluster (LoadBalancer / NodePort). */
  internetExposed: boolean;
  /** Workload runs as UID 0. */
  runAsRoot: boolean;
  /** Workload runs privileged. */
  privileged: boolean;
  /** Excessive privilege: privileged, root, hostNetwork/Path, escalation, or cluster-admin SA. */
  overPrivileged: boolean;
  /** The workload's service account can read Secrets (directly or as cluster-admin). */
  canReachSecret: boolean;
  /** Node / control-plane level finding (kube-bench) — not workload-scoped. */
  isNode: boolean;
  /** True overall reachability verdict: running AND exposed (workload findings only). */
  reachable?: boolean;
}

export interface ReachabilityResult {
  /** Findings with `reachable` + `exploitScore` set, sorted by exploitScore desc. */
  findings: Finding[];
  /** Context per finding id (used by correlation + the NL query engine). */
  contexts: Map<string, FindingContext>;
}

/** Severity → score base. Leaves headroom for reachability bonuses (max 100). */
const SEVERITY_BASE: Record<Severity, number> = {
  critical: 85,
  high: 60,
  medium: 35,
  low: 15,
  info: 3,
};

/**
 * Enrich every finding with reachability + an exploit score, and return the
 * derived per-finding context. Findings are returned sorted by exploitScore so
 * the UI/report list is reachability-ranked, not CVSS-ranked.
 */
export function analyzeReachability(
  findings: Finding[],
  inventory: ClusterInventory,
): ReachabilityResult {
  const index = indexInventory(inventory);
  const contexts = new Map<string, FindingContext>();

  const enriched = findings.map((f) => {
    const ctx = buildContext(f, index);
    contexts.set(f.id, ctx);
    const reachable = ctx.linked ? ctx.running && ctx.exposed : undefined;
    return {
      ...f,
      reachable,
      exploitScore: scoreFinding(f.severity, ctx),
    };
  });

  enriched.sort(
    (a, b) =>
      (b.exploitScore ?? 0) - (a.exploitScore ?? 0) ||
      a.id.localeCompare(b.id), // stable tiebreak
  );

  return { findings: enriched, contexts };
}

/** Reachability-weighted exploitability in [0,100]. Reachability, not CVSS, decides rank. */
export function scoreFinding(severity: Severity, ctx: FindingContext): number {
  let score = SEVERITY_BASE[severity];

  if (ctx.linked) {
    if (!ctx.running) {
      // Dormant workload: a critical vuln that isn't running is far less urgent.
      score *= 0.25;
    } else {
      if (ctx.internetExposed) score += 12;
      else if (ctx.exposed) score += 6;
      if (ctx.overPrivileged) score += 8;
      if (ctx.canReachSecret) score += 8;
    }
  }
  // Node/cluster-level findings (kube-bench) keep their severity base: they are
  // not reachability-scoped, but they are real control-plane exposure.

  return clamp(Math.round(score));
}

// ---- Inventory index ------------------------------------------------------

interface InventoryIndex {
  workloads: WorkloadInfo[];
  /** workload key (ns/name) → exposed-Service facts. */
  exposure: Map<string, { exposed: boolean; internet: boolean }>;
  /** serviceAccount key (ns/sa) → secret/admin reach. */
  secretReach: Map<string, { canReadSecrets: boolean; clusterAdmin: boolean }>;
}

function indexInventory(inv: ClusterInventory): InventoryIndex {
  const exposure = new Map<string, { exposed: boolean; internet: boolean }>();
  for (const w of inv.workloads) {
    const facts = serviceExposure(w, inv.services);
    exposure.set(workloadKey(w.namespace, w.name), facts);
  }
  const secretReach = new Map<string, { canReadSecrets: boolean; clusterAdmin: boolean }>();
  for (const s of inv.rbac) {
    secretReach.set(saKey(s.namespace, s.serviceAccount), {
      canReadSecrets: s.canReadSecrets,
      clusterAdmin: s.clusterAdmin,
    });
  }
  return { workloads: inv.workloads, exposure, secretReach };
}

/** Does any exposed Service select this workload? Is any of them internet-facing? */
function serviceExposure(
  w: WorkloadInfo,
  services: ServiceInfo[],
): { exposed: boolean; internet: boolean } {
  let exposed = false;
  let internet = false;
  for (const s of services) {
    if (s.namespace !== w.namespace) continue;
    if (!selectorMatchesWorkload(s.selector, w)) continue;
    // A Service "routes to" the workload; whether traffic can actually arrive
    // depends on the Service type / explicit exposed flag.
    const svcExposed = s.exposed || s.type === 'LoadBalancer' || s.type === 'NodePort';
    exposed = true; // reachable at least within the namespace
    if (svcExposed) internet = true;
  }
  return { exposed: exposed || internet, internet };
}

/**
 * A label selector matches a workload when every selector label is present on
 * the workload. We don't carry full pod labels in the inventory, so we use the
 * conventional `app: <name>` and `app.kubernetes.io/name: <name>` heuristics
 * plus an exact workload-name match.
 */
function selectorMatchesWorkload(selector: Record<string, string>, w: WorkloadInfo): boolean {
  const keys = Object.keys(selector);
  if (keys.length === 0) return false; // empty selector → not a meaningful route
  const appLabels = [selector['app'], selector['app.kubernetes.io/name'], selector['k8s-app']];
  return appLabels.some((v) => v !== undefined && v === w.name);
}

function buildContext(f: Finding, index: InventoryIndex): FindingContext {
  const isNode = f.resource.kind === 'Node';
  const workload = isNode ? undefined : matchWorkload(f.resource, index.workloads);

  if (!workload) {
    return {
      findingId: f.id,
      linked: false,
      running: false,
      exposed: false,
      internetExposed: false,
      runAsRoot: false,
      privileged: false,
      overPrivileged: false,
      canReachSecret: false,
      isNode,
    };
  }

  const exposure = index.exposure.get(workloadKey(workload.namespace, workload.name)) ?? {
    exposed: false,
    internet: false,
  };
  const sa = index.secretReach.get(saKey(workload.namespace, workload.serviceAccount)) ?? {
    canReadSecrets: false,
    clusterAdmin: false,
  };
  const running = workload.running && workload.replicas > 0;
  const overPrivileged =
    workload.privileged ||
    workload.runAsRoot ||
    workload.hostNetwork ||
    workload.hostPath ||
    workload.allowPrivilegeEscalation ||
    sa.clusterAdmin;
  const canReachSecret = sa.canReadSecrets || sa.clusterAdmin;

  return {
    findingId: f.id,
    workload: { namespace: workload.namespace, kind: workload.kind, name: workload.name },
    linked: true,
    running,
    exposed: exposure.exposed,
    internetExposed: exposure.internet,
    runAsRoot: workload.runAsRoot,
    privileged: workload.privileged,
    overPrivileged,
    canReachSecret,
    isNode: false,
    reachable: running && exposure.exposed,
  };
}

/**
 * Attribute a finding's resource to a workload. Scanners disagree on shape:
 *  - Trivy: kind "Image", name "repo:tag (distro x.y)" → match by image prefix.
 *  - Kubescape: kind Deployment/StatefulSet/… + namespace + name → direct.
 *  - Falco: kind "Pod", name "<deploy>-<rs-hash>-<pod-hash>" → strip the suffix.
 */
export function matchWorkload(
  resource: ResourceRef,
  workloads: WorkloadInfo[],
): WorkloadInfo | undefined {
  const kind = resource.kind;

  if (kind === 'Image' || resource.image) {
    const ref = baseImage(resource.image ?? resource.name);
    return workloads.find((w) => w.images.some((img) => baseImage(img) === ref));
  }

  if (kind === 'Pod') {
    const base = podOwnerName(resource.name);
    return workloads.find(
      (w) =>
        sameNs(w.namespace, resource.namespace) &&
        (w.name === resource.name || w.name === base || resource.name.startsWith(`${w.name}-`)),
    );
  }

  // Deployment / StatefulSet / DaemonSet / Service / ReplicaSet / etc.
  const direct = workloads.find(
    (w) => sameNs(w.namespace, resource.namespace) && w.name === resource.name,
  );
  if (direct) return direct;

  // Service finding (kind Service) → the workload it fronts, by name convention.
  if (kind === 'Service') {
    const svcBase = resource.name.replace(/-(svc|service)$/i, '');
    return workloads.find(
      (w) => sameNs(w.namespace, resource.namespace) && (w.name === svcBase || w.name === resource.name),
    );
  }

  return undefined;
}

/** "repo:tag (debian 12.1)" → "repo:tag"; trims any parenthetical distro suffix. */
function baseImage(image: string): string {
  return image.replace(/\s*\(.*\)\s*$/, '').trim();
}

/** "payment-api-7d9f8c5b4-xk2lq" → "payment-api" (strip ReplicaSet + Pod hashes). */
function podOwnerName(pod: string): string {
  return pod.replace(/-[a-z0-9]{6,10}-[a-z0-9]{5}$/i, '').replace(/-[a-z0-9]{5}$/i, '');
}

function sameNs(a?: string, b?: string): boolean {
  return (a ?? '') === (b ?? '');
}

function workloadKey(ns: string, name: string): string {
  return `${ns}/${name}`;
}

function saKey(ns: string, sa: string): string {
  return `${ns}/${sa}`;
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, n));
}
