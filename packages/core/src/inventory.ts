import { z } from 'zod';

/**
 * Read-only cluster inventory the Collector gathers and the Analyst reasons
 * over. This is the context that turns a raw finding into a *reachable* one:
 * is the workload actually running, internet-exposed, over-privileged, and can
 * it reach a secret?
 */

export const WorkloadInfoSchema = z.object({
  kind: z.string(), // Deployment, StatefulSet, DaemonSet, Pod, ...
  name: z.string(),
  namespace: z.string(),
  images: z.array(z.string()).default([]),
  /** Desired/observed replicas; 0 means scaled down (not running). */
  replicas: z.number().int().nonnegative().default(1),
  running: z.boolean().default(true),
  serviceAccount: z.string().default('default'),
  // securityContext-derived risk flags:
  privileged: z.boolean().default(false),
  runAsRoot: z.boolean().default(false),
  hostNetwork: z.boolean().default(false),
  hostPath: z.boolean().default(false),
  allowPrivilegeEscalation: z.boolean().default(false),
});
export type WorkloadInfo = z.infer<typeof WorkloadInfoSchema>;

export const ServiceInfoSchema = z.object({
  name: z.string(),
  namespace: z.string(),
  type: z.enum(['ClusterIP', 'NodePort', 'LoadBalancer', 'ExternalName']).default('ClusterIP'),
  /** Reachable from outside the cluster (LoadBalancer / NodePort / Ingress). */
  exposed: z.boolean().default(false),
  selector: z.record(z.string()).default({}),
  ports: z.array(z.number()).default([]),
});
export type ServiceInfo = z.infer<typeof ServiceInfoSchema>;

export const RbacSubjectSchema = z.object({
  serviceAccount: z.string(),
  namespace: z.string(),
  /** Can this SA read Secret objects (directly or via wildcard)? */
  canReadSecrets: z.boolean().default(false),
  /** Bound to cluster-admin or an equivalent take-over role. */
  clusterAdmin: z.boolean().default(false),
  roles: z.array(z.string()).default([]),
});
export type RbacSubject = z.infer<typeof RbacSubjectSchema>;

export const NetworkPolicyInfoSchema = z.object({
  name: z.string(),
  namespace: z.string(),
  /** Pod selector the policy applies to ({} = whole namespace). */
  appliesTo: z.record(z.string()).default({}),
});
export type NetworkPolicyInfo = z.infer<typeof NetworkPolicyInfoSchema>;

export const ClusterInventorySchema = z.object({
  collectedAt: z.string().datetime(),
  /** True when gathered from a fixture rather than a live cluster. */
  fromFixture: z.boolean().default(false),
  namespaces: z.array(z.string()).default([]),
  workloads: z.array(WorkloadInfoSchema).default([]),
  services: z.array(ServiceInfoSchema).default([]),
  rbac: z.array(RbacSubjectSchema).default([]),
  networkPolicies: z.array(NetworkPolicyInfoSchema).default([]),
});
export type ClusterInventory = z.infer<typeof ClusterInventorySchema>;

/** Does the namespace have at least one NetworkPolicy (i.e. not wide-open)? */
export function namespaceHasNetworkPolicy(inv: ClusterInventory, namespace: string): boolean {
  return inv.networkPolicies.some((np) => np.namespace === namespace);
}
