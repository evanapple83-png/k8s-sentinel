import 'server-only';
import { supabaseAdmin } from './supabase/server';
import { AccessError, recordAudit, requireMembership, requireRole } from './data';
import { chartOciRef } from './chart';

/** Confirm a cluster id actually belongs to the account before touching it. */
async function assertClusterInAccount(accountId: string, clusterId: string): Promise<void> {
  const db = supabaseAdmin();
  const { data } = await db
    .from('cluster')
    .select('id')
    .eq('id', clusterId)
    .eq('account_id', accountId)
    .maybeSingle();
  if (!data) throw new AccessError('cluster not in account');
}

/**
 * Permissions UX (1F). Plain-English rendering of what the in-cluster agent can
 * see (derived from the read-only ClusterRole the Helm chart installs), plus an
 * opt-in catalog of elevated capabilities. Users never write YAML — each toggle
 * surfaces a copy-paste `kubectl`/`helm` snippet, and every change is audited.
 */

export interface PermissionStatement {
  can: string;
  resources: string;
  note?: string;
}

/** What the baseline read-only ClusterRole grants (deploy/helm rbac.yaml). */
export const BASELINE_READS: PermissionStatement[] = [
  {
    can: 'See workloads & infrastructure',
    resources:
      'pods, deployments, daemonsets, statefulsets, replicasets, jobs, cronjobs, nodes, namespaces',
  },
  {
    can: 'See networking',
    resources: 'services, endpoints, ingresses, network policies',
  },
  {
    can: 'See config & storage',
    resources: 'configmaps, persistent volumes & claims',
  },
  {
    can: 'See access control (RBAC)',
    resources: 'roles, rolebindings, clusterroles, clusterrolebindings, service accounts',
  },
  {
    can: 'Know which secrets exist',
    resources: 'secret names & metadata only',
    note: 'Never reads secret VALUES — only whether a secret exists and who can reach it.',
  },
  {
    can: 'See extensions & policies',
    resources: 'custom resource definitions, pod disruption budgets',
  },
];

/** What the agent fundamentally cannot do at baseline. */
export const BASELINE_CANNOT: string[] = [
  'Create, modify, or delete any resource (get/list/watch only)',
  'Read Secret contents / data',
  'Exec into containers or read pod logs',
  'Access the kubeconfig or cluster credentials',
];

export type Risk = 'low' | 'medium' | 'high';

export interface Capability {
  key: string;
  label: string;
  description: string;
  risk: Risk;
  scope: 'cluster' | 'integration';
  /** Copy-paste snippet the user applies to grant it. No YAML authoring needed. */
  snippet: string;
}

export const CAPABILITIES: Capability[] = [
  {
    key: 'github-fix-prs',
    label: 'Open fix PRs via GitHub App',
    description:
      'Let Sentinel open remediation pull requests in your repos. This is an external GitHub App install — no extra cluster permission. Still propose-only: you review and merge.',
    risk: 'low',
    scope: 'integration',
    snippet: `# Install the GitHub App and grant it the target repos:
#   https://github.com/apps/k8s-sentinel/installations/new
# No kubectl needed — this grants no in-cluster access.`,
  },
  {
    key: 'pod-logs',
    label: 'Read pod logs',
    description:
      'Allow the agent to read container logs for richer correlation. Logs may contain sensitive data, so this is off by default.',
    risk: 'medium',
    scope: 'cluster',
    snippet: `kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sentinel-readonly-logs
rules:
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get", "list"]
EOF
kubectl create clusterrolebinding sentinel-readonly-logs \\
  --clusterrole=sentinel-readonly-logs \\
  --serviceaccount=sentinel:sentinel-sa`,
  },
  {
    key: 'runtime-falco',
    label: 'Runtime detection (Falco)',
    description:
      'Deploy the Falco DaemonSet to watch syscalls for live attack behaviour. Requires privileged host access on each node — medium risk, isolated to the detection sidecar.',
    risk: 'medium',
    scope: 'cluster',
    snippet: `helm upgrade sentinel ${chartOciRef()} \\
  --reuse-values --set falco.enabled=true`,
  },
  {
    key: 'read-secret-data',
    label: 'Read Secret contents',
    description:
      'Allow deep analysis of secret material (weak keys, expired certs, embedded credentials). This materially increases blast radius — leave off unless you need it.',
    risk: 'high',
    scope: 'cluster',
    snippet: `kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sentinel-secret-read
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]   # baseline grants only "list" (names); this adds value reads
EOF
kubectl create clusterrolebinding sentinel-secret-read \\
  --clusterrole=sentinel-secret-read \\
  --serviceaccount=sentinel:sentinel-sa`,
  },
];

export interface CapabilityState extends Capability {
  enabled: boolean;
}

/** Catalog merged with this cluster's enabled state (membership-guarded). */
export async function getCapabilities(
  userId: string,
  accountId: string,
  clusterId: string,
): Promise<CapabilityState[]> {
  await requireMembership(userId, accountId);
  await assertClusterInAccount(accountId, clusterId);
  const db = supabaseAdmin();
  const { data } = await db
    .from('cluster_capability')
    .select('key, enabled')
    .eq('cluster_id', clusterId);
  const enabled = new Map((data ?? []).map((r) => [r.key as string, Boolean(r.enabled)]));
  return CAPABILITIES.map((c) => ({ ...c, enabled: enabled.get(c.key) ?? false }));
}

/** Toggle a capability (admin only). Persists + writes an audit entry. */
export async function setCapability(
  userId: string,
  accountId: string,
  clusterId: string,
  key: string,
  enabled: boolean,
  actorEmail: string,
): Promise<void> {
  if (!CAPABILITIES.some((c) => c.key === key)) throw new Error(`unknown capability: ${key}`);
  await requireRole(userId, accountId, 'admin');
  await assertClusterInAccount(accountId, clusterId);

  const db = supabaseAdmin();
  const { error } = await db.from('cluster_capability').upsert(
    { cluster_id: clusterId, key, enabled, updated_at: new Date().toISOString(), updated_by: userId },
    { onConflict: 'cluster_id,key' },
  );
  if (error) throw error;

  await recordAudit({
    accountId,
    actor: actorEmail,
    action: enabled ? 'capability.enabled' : 'capability.disabled',
    clusterId,
    detail: { capability: key },
  });
}
