import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  ClusterInventorySchema,
  type ClusterInventory,
  type RbacSubject,
  type ServiceInfo,
  type WorkloadInfo,
} from '@k8s-sentinel/core';
import { fixtureInventory } from './inventory-fixture.js';

export interface InventoryTarget {
  kubeconfig?: string;
  namespace?: string;
}

/** Is a kubeconfig reachable (explicit, env, or default ~/.kube/config)? */
function resolveKubeconfig(target: InventoryTarget): string | undefined {
  if (target.kubeconfig && existsSync(target.kubeconfig)) return target.kubeconfig;
  if (process.env.KUBECONFIG && existsSync(process.env.KUBECONFIG)) return process.env.KUBECONFIG;
  const def = join(homedir(), '.kube', 'config');
  return existsSync(def) ? def : undefined;
}

/**
 * Gather a read-only inventory of the cluster. Connects with the (read-only)
 * service-account kubeconfig when available; otherwise returns the bundled
 * fixture so the pipeline runs offline. Any connection error degrades to the
 * fixture rather than failing the scan.
 */
export async function collectInventory(target: InventoryTarget = {}): Promise<ClusterInventory> {
  const kubeconfig = resolveKubeconfig(target);
  if (!kubeconfig) return fixtureInventory();

  try {
    return await collectLive(kubeconfig, target.namespace);
  } catch (err) {
    const inv = fixtureInventory();
    // eslint-disable-next-line no-console
    console.warn(`[collector] live inventory failed (${(err as Error).message}); using fixture`);
    return inv;
  }
}

/** Live, read-only collection via @kubernetes/client-node (loaded lazily). */
async function collectLive(kubeconfigPath: string, namespace?: string): Promise<ClusterInventory> {
  const pkg = '@kubernetes/client-node';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const k8s: any = await import(/* @vite-ignore */ pkg);
  const kc = new k8s.KubeConfig();
  kc.loadFromFile(kubeconfigPath);

  const core = kc.makeApiClient(k8s.CoreV1Api);
  const apps = kc.makeApiClient(k8s.AppsV1Api);
  const rbac = kc.makeApiClient(k8s.RbacAuthorizationV1Api);
  const net = kc.makeApiClient(k8s.NetworkingV1Api);

  const list = async <T>(fn: () => Promise<{ items?: T[] } | { body: { items?: T[] } }>): Promise<T[]> => {
    const res = (await fn()) as { items?: T[]; body?: { items?: T[] } };
    return res.items ?? res.body?.items ?? [];
  };

  const [nsList, deploys, svcs, sas, roleBindings, clusterRoleBindings, netpols] = await Promise.all([
    list<KObj>(() => core.listNamespace()),
    list<KObj>(() => (namespace ? apps.listNamespacedDeployment({ namespace }) : apps.listDeploymentForAllNamespaces())),
    list<KObj>(() => (namespace ? core.listNamespacedService({ namespace }) : core.listServiceForAllNamespaces())),
    list<KObj>(() => (namespace ? core.listNamespacedServiceAccount({ namespace }) : core.listServiceAccountForAllNamespaces())),
    list<KObj>(() => (namespace ? rbac.listNamespacedRoleBinding({ namespace }) : rbac.listRoleBindingForAllNamespaces())),
    list<KObj>(() => rbac.listClusterRoleBinding()),
    list<KObj>(() => (namespace ? net.listNamespacedNetworkPolicy({ namespace }) : net.listNetworkPolicyForAllNamespaces())),
  ]);

  const workloads: WorkloadInfo[] = deploys.map(toWorkload);
  const services: ServiceInfo[] = svcs.map(toService);
  const rbacSubjects = deriveRbac(sas, roleBindings, clusterRoleBindings);
  const networkPolicies = netpols.map((np) => ({
    name: np.metadata?.name ?? 'unknown',
    namespace: np.metadata?.namespace ?? 'default',
    appliesTo: np.spec?.podSelector?.matchLabels ?? {},
  }));

  return ClusterInventorySchema.parse({
    collectedAt: new Date().toISOString(),
    fromFixture: false,
    namespaces: nsList.map((n) => n.metadata?.name).filter(Boolean),
    workloads,
    services,
    rbac: rbacSubjects,
    networkPolicies,
  });
}

function toWorkload(d: KObj): WorkloadInfo {
  const spec = d.spec ?? {};
  const podSpec = spec.template?.spec ?? {};
  const containers = podSpec.containers ?? [];
  const sc = containers[0]?.securityContext ?? {};
  const podSc = podSpec.securityContext ?? {};
  return {
    kind: d.kind ?? 'Deployment',
    name: d.metadata?.name ?? 'unknown',
    namespace: d.metadata?.namespace ?? 'default',
    images: containers.map((c: { image?: string }) => c.image).filter(Boolean) as string[],
    replicas: spec.replicas ?? 0,
    running: (spec.replicas ?? 0) > 0,
    serviceAccount: podSpec.serviceAccountName ?? 'default',
    privileged: Boolean(sc.privileged),
    runAsRoot: sc.runAsNonRoot === false || podSc.runAsUser === 0,
    hostNetwork: Boolean(podSpec.hostNetwork),
    hostPath: (podSpec.volumes ?? []).some((v: { hostPath?: unknown }) => Boolean(v.hostPath)),
    allowPrivilegeEscalation: Boolean(sc.allowPrivilegeEscalation),
  };
}

function toService(s: KObj): ServiceInfo {
  const type = s.spec?.type ?? 'ClusterIP';
  return {
    name: s.metadata?.name ?? 'unknown',
    namespace: s.metadata?.namespace ?? 'default',
    type,
    exposed: type === 'LoadBalancer' || type === 'NodePort',
    selector: s.spec?.selector ?? {},
    ports: (s.spec?.ports ?? [])
      .map((p: { port?: number }) => p.port)
      .filter((p: unknown): p is number => typeof p === 'number'),
  };
}

/** Best-effort: which SAs are bound to secret-reading / cluster-admin roles. */
function deriveRbac(sas: KObj[], roleBindings: KObj[], clusterRoleBindings: KObj[]): RbacSubject[] {
  const adminRoles = new Set(['cluster-admin', 'admin']);
  const bindingsFor = (sa: KObj): string[] => {
    const name = sa.metadata?.name;
    const ns = sa.metadata?.namespace;
    const roles: string[] = [];
    for (const rb of [...roleBindings, ...clusterRoleBindings]) {
      const subjects = rb.subjects ?? [];
      if (subjects.some((sub) => sub.kind === 'ServiceAccount' && sub.name === name && (!sub.namespace || sub.namespace === ns))) {
        if (rb.roleRef?.name) roles.push(rb.roleRef.name);
      }
    }
    return roles;
  };
  return sas.map((sa) => {
    const roles = bindingsFor(sa);
    const clusterAdmin = roles.some((r) => adminRoles.has(r));
    return {
      serviceAccount: sa.metadata?.name ?? 'default',
      namespace: sa.metadata?.namespace ?? 'default',
      canReadSecrets: clusterAdmin || roles.some((r) => /secret|view|edit|admin/i.test(r)),
      clusterAdmin,
      roles,
    };
  });
}

/** Minimal structural view of K8s objects we touch (read-only). */
interface KObj {
  kind?: string;
  metadata?: { name?: string; namespace?: string };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  spec?: any;
  subjects?: { kind?: string; name?: string; namespace?: string }[];
  roleRef?: { name?: string };
}
