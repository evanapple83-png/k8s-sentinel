import type { AttackPath, Fix, Finding, RunRecord, RunSnapshot } from './types';

/**
 * Demo dataset — the real "payment-api" scenario the offline scanners produce
 * (risk 100/100). Lets every screen render a faithful product preview before
 * Supabase/auth are wired (1C/1D swap this for live, tenant-scoped data).
 */

const RUN_ID = 'run-demo-001';

export const DEMO_RUN: RunRecord = {
  id: RUN_ID,
  clusterId: 'cluster-demo',
  createdAt: '2026-05-27T09:14:00.000Z',
  status: 'complete',
  engine: 'claude',
  usedFixtures: true,
  findingCount: 12,
  pathCount: 2,
  riskScore: 100,
  summary:
    'Internet-exposed payment-api runs privileged as root with a critical CVE and a service account that can read cluster Secrets — a complete external-to-secret attack path.',
};

/** Previous run, for the "since last scan" delta on Overview. */
export const DEMO_PREV_RUN: Pick<RunRecord, 'findingCount' | 'pathCount' | 'riskScore'> = {
  findingCount: 14,
  pathCount: 3,
  riskScore: 100,
};

const f = (x: Finding): Finding => x;

export const DEMO_FINDINGS: Finding[] = [
  f({
    id: 'falco:1a2b',
    source: 'falco',
    ruleId: 'Read sensitive file untrusted',
    title: 'Read sensitive file untrusted',
    description:
      'A process inside the payment-api container read /etc/shadow — a strong indicator of credential theft on a running, internet-exposed workload.',
    severity: 'critical',
    resource: { kind: 'Pod', name: 'payment-api-7d9f8c5b4-xk2lq', namespace: 'prod' },
    reachable: true,
    exploitScore: 100,
    attackPathId: 'path-1',
    controls: [{ framework: 'MITRE-ATTACK', id: 'T1552.001', title: 'Credentials in Files' }],
  }),
  f({
    id: 'trivy:3c4d',
    source: 'trivy',
    ruleId: 'CVE-2023-0286',
    title: 'X.400 address type confusion in X.509 GeneralName',
    description:
      'A type confusion in OpenSSL X.400 address processing can lead to memory corruption / DoS, reachable from TLS handling on the exposed payment-api.',
    severity: 'critical',
    resource: { kind: 'Image', name: 'payment-api:1.2.0', image: 'payment-api:1.2.0 (debian 12.1)' },
    reachable: true,
    exploitScore: 100,
    attackPathId: 'path-1',
    baseScore: 7.4,
    controls: [{ framework: 'CIS', id: 'CIS-5.1.3' }],
  }),
  f({
    id: 'kubescape:5e6f',
    source: 'kubescape',
    ruleId: 'C-0035',
    title: 'Workloads with cluster-takeover roles',
    description:
      'The payment-sa service account is bound to a role that can read Secrets cluster-wide — a privilege-escalation and secret-access primitive.',
    severity: 'high',
    resource: { kind: 'Deployment', name: 'payment-api', namespace: 'prod' },
    reachable: true,
    exploitScore: 88,
    attackPathId: 'path-1',
    controls: [
      { framework: 'NSA-CISA', id: 'RBAC' },
      { framework: 'CIS', id: 'CIS-5.1.1' },
    ],
  }),
  f({
    id: 'kubescape:7a8b',
    source: 'kubescape',
    ruleId: 'C-0057',
    title: 'Privileged container',
    description:
      'payment-api runs with privileged: true, granting host-level capabilities and breaking container isolation.',
    severity: 'high',
    resource: { kind: 'Deployment', name: 'payment-api', namespace: 'prod' },
    reachable: true,
    exploitScore: 88,
    attackPathId: 'path-1',
    controls: [{ framework: 'NSA-CISA', id: 'PodSecurity' }],
  }),
  f({
    id: 'kubescape:9c0d',
    source: 'kubescape',
    ruleId: 'C-0256',
    title: 'Exposure to internet',
    description:
      'payment-api-svc is a LoadBalancer exposed to 0.0.0.0/0, making the workload reachable from the public internet.',
    severity: 'high',
    resource: { kind: 'Service', name: 'payment-api-svc', namespace: 'prod' },
    reachable: true,
    exploitScore: 88,
    attackPathId: 'path-1',
    controls: [{ framework: 'CIS', id: 'CIS-5.7.3' }],
  }),
  f({
    id: 'trivy:1e2f',
    source: 'trivy',
    ruleId: 'CVE-2022-37434',
    title: 'zlib: heap-based buffer over-read in inflate via large gzip header',
    description:
      'A heap over-read in zlib inflate() reachable via attacker-controlled gzip input on the exposed service.',
    severity: 'high',
    resource: { kind: 'Image', name: 'payment-api:1.2.0', image: 'payment-api:1.2.0 (debian 12.1)' },
    reachable: true,
    exploitScore: 84,
    attackPathId: 'path-1',
    baseScore: 7.5,
    controls: [{ framework: 'CIS', id: 'CIS-5.1.3' }],
  }),
  f({
    id: 'falco:3a4b',
    source: 'falco',
    ruleId: 'Terminal shell in container',
    title: 'Terminal shell in container',
    description: 'An interactive shell (/bin/bash) was spawned inside the payment-api container.',
    severity: 'medium',
    resource: { kind: 'Pod', name: 'payment-api-7d9f8c5b4-xk2lq', namespace: 'prod' },
    reachable: true,
    exploitScore: 63,
    controls: [{ framework: 'MITRE-ATTACK', id: 'T1059' }],
  }),
  f({
    id: 'kube-bench:5c6d',
    source: 'kube-bench',
    ruleId: '1.2.1',
    title: 'Ensure that the --anonymous-auth argument is set to false',
    description: 'The API server permits anonymous requests; set --anonymous-auth=false.',
    severity: 'high',
    resource: { kind: 'Node', name: 'master' },
    reachable: false,
    exploitScore: 60,
    controls: [{ framework: 'CIS', id: 'CIS-1.2.1' }],
  }),
  f({
    id: 'trivy:7e8f',
    source: 'trivy',
    ruleId: 'CVE-2023-5678',
    title: 'Generate/check DH keys excessively long',
    description: 'A DoS in OpenSSL DH key generation; lower severity on the internal frontend.',
    severity: 'medium',
    resource: { kind: 'Image', name: 'frontend:2.4.1', image: 'frontend:2.4.1 (alpine 3.18)' },
    reachable: true,
    exploitScore: 41,
    attackPathId: 'path-2',
    baseScore: 5.3,
  }),
  f({
    id: 'kubescape:9a0b',
    source: 'kubescape',
    ruleId: 'C-0016',
    title: 'Allow privilege escalation',
    description: 'allowPrivilegeEscalation is not set to false on the frontend container.',
    severity: 'medium',
    resource: { kind: 'Deployment', name: 'frontend', namespace: 'prod' },
    reachable: true,
    exploitScore: 38,
    attackPathId: 'path-2',
    controls: [{ framework: 'NSA-CISA', id: 'PodSecurity' }],
  }),
  f({
    id: 'kubescape:1c2d',
    source: 'kubescape',
    ruleId: 'C-0048',
    title: 'HostPath mount',
    description: 'A hostPath volume is mounted into the logging DaemonSet, widening blast radius.',
    severity: 'low',
    resource: { kind: 'DaemonSet', name: 'fluentd', namespace: 'logging' },
    reachable: false,
    exploitScore: 18,
    controls: [{ framework: 'CIS', id: 'CIS-5.2.4' }],
  }),
  f({
    id: 'trivy:3e4f',
    source: 'trivy',
    ruleId: 'CVE-2024-2961',
    title: 'glibc iconv buffer overflow',
    description: 'A bounded buffer overflow in glibc iconv; not reachable from the frontend path.',
    severity: 'low',
    resource: { kind: 'Image', name: 'frontend:2.4.1', image: 'frontend:2.4.1 (alpine 3.18)' },
    reachable: false,
    exploitScore: 12,
    baseScore: 4.3,
  }),
];

export const DEMO_PATHS: AttackPath[] = [
  {
    id: 'path-1',
    score: 100,
    entryPoint: 'internet',
    narrative:
      'Internet-exposed Deployment prod/payment-api is running (3 replicas), carries a critical vulnerability (Read sensitive file untrusted and 2 more), runs privileged and as root, and its service account "payment-sa" can read cluster Secrets — a full external-to-secret attack path.',
    findingIds: ['falco:1a2b', 'trivy:3c4d', 'kubescape:5e6f', 'kubescape:7a8b', 'kubescape:9c0d'],
    steps: [
      {
        kind: 'exposed',
        resource: { kind: 'Service', name: 'payment-api-svc', namespace: 'prod' },
        detail: 'LoadBalancer reachable from 0.0.0.0/0',
        findingIds: ['kubescape:9c0d'],
      },
      {
        kind: 'running',
        resource: { kind: 'Deployment', name: 'payment-api', namespace: 'prod' },
        detail: '3 replicas running image payment-api:1.2.0',
        findingIds: [],
      },
      {
        kind: 'vulnerable',
        resource: { kind: 'Image', name: 'payment-api:1.2.0' },
        detail: 'Critical OpenSSL CVE-2023-0286 + active Falco detection',
        findingIds: ['trivy:3c4d', 'falco:1a2b'],
      },
      {
        kind: 'over-privileged',
        resource: { kind: 'Deployment', name: 'payment-api', namespace: 'prod' },
        detail: 'privileged: true, runs as root (uid 0)',
        findingIds: ['kubescape:7a8b'],
      },
      {
        kind: 'secret-access',
        resource: { kind: 'ServiceAccount', name: 'payment-sa', namespace: 'prod' },
        detail: 'Bound to a role that reads Secrets cluster-wide',
        findingIds: ['kubescape:5e6f'],
      },
    ],
  },
  {
    id: 'path-2',
    score: 41,
    entryPoint: 'namespace',
    narrative:
      'Namespace-reachable Deployment prod/frontend is running (2 replicas) and carries a medium vulnerability CVE-2023-5678 with privilege-escalation allowed.',
    findingIds: ['trivy:7e8f', 'kubescape:9a0b'],
    steps: [
      {
        kind: 'running',
        resource: { kind: 'Deployment', name: 'frontend', namespace: 'prod' },
        detail: '2 replicas running image frontend:2.4.1',
        findingIds: [],
      },
      {
        kind: 'vulnerable',
        resource: { kind: 'Image', name: 'frontend:2.4.1' },
        detail: 'Medium OpenSSL CVE-2023-5678',
        findingIds: ['trivy:7e8f'],
      },
      {
        kind: 'over-privileged',
        resource: { kind: 'Deployment', name: 'frontend', namespace: 'prod' },
        detail: 'allowPrivilegeEscalation not disabled',
        findingIds: ['kubescape:9a0b'],
      },
    ],
  },
];

export const DEMO_FIXES: Fix[] = [
  {
    id: 'fix-pin-image',
    playbookId: 'pin-image',
    title: 'Pin payment-api to a patched image',
    severity: 'critical',
    kind: 'patch',
    rationale:
      'Rebuild payment-api on a base image with the patched OpenSSL (CVE-2023-0286) and zlib (CVE-2022-37434), and pin by digest so the fix is reproducible.',
    path: 'k8s/prod/payment-api-deployment.yaml',
    diff: `--- a/k8s/prod/payment-api-deployment.yaml
+++ b/k8s/prod/payment-api-deployment.yaml
@@ spec.template.spec.containers[0]
       containers:
         - name: payment-api
-          image: payment-api:1.2.0
+          image: payment-api:1.2.1@sha256:9f2c…patched
           ports:
             - containerPort: 8080`,
    manualSteps: [
      'Rebuild payment-api on debian 12.5 (OpenSSL ≥ 3.0.8, zlib ≥ 1.2.13).',
      'Push and record the image digest.',
    ],
    controls: [{ framework: 'CIS', id: 'CIS-5.1.3' }],
    findingIds: ['trivy:3c4d', 'trivy:1e2f'],
    attackPathId: 'path-1',
    priority: 1,
    status: 'proposed',
    branch: 'sentinel/pin-payment-api-image',
    prTitle: 'Pin payment-api to patched image (CVE-2023-0286, CVE-2022-37434)',
    prBody: 'Proposed by K8s Sentinel. Reachability-ranked #1 on attack path path-1.',
  },
  {
    id: 'fix-drop-privileged',
    playbookId: 'drop-privileged',
    title: 'Drop privileged + run as non-root',
    severity: 'high',
    kind: 'patch',
    rationale:
      'Remove privileged mode, disable privilege escalation, and run as a non-root user to break the host-level escalation primitive.',
    path: 'k8s/prod/payment-api-deployment.yaml',
    diff: `--- a/k8s/prod/payment-api-deployment.yaml
+++ b/k8s/prod/payment-api-deployment.yaml
@@ spec.template.spec.containers[0]
           securityContext:
-            privileged: true
+            privileged: false
+            allowPrivilegeEscalation: false
+            runAsNonRoot: true
+            runAsUser: 65532
+            readOnlyRootFilesystem: true
+            capabilities:
+              drop: ["ALL"]`,
    manualSteps: ['Confirm payment-api does not require root or host capabilities.'],
    controls: [{ framework: 'NSA-CISA', id: 'PodSecurity' }],
    findingIds: ['kubescape:7a8b'],
    attackPathId: 'path-1',
    priority: 2,
    status: 'proposed',
    branch: 'sentinel/drop-privileged-payment-api',
    prTitle: 'Harden payment-api securityContext (drop privileged)',
    prBody: 'Proposed by K8s Sentinel. Reachability-ranked #2 on attack path path-1.',
  },
  {
    id: 'fix-restrict-rbac',
    playbookId: 'restrict-rbac',
    title: 'Restrict payment-sa to least privilege',
    severity: 'high',
    kind: 'patch',
    rationale:
      'Replace the cluster-wide Secret-read binding with a namespaced Role limited to the two Secrets payment-api actually needs.',
    path: 'k8s/prod/payment-sa-rbac.yaml',
    diff: `--- a/k8s/prod/payment-sa-rbac.yaml
+++ b/k8s/prod/payment-sa-rbac.yaml
@@
-kind: ClusterRoleBinding
-roleRef:
-  kind: ClusterRole
-  name: secret-reader
+kind: RoleBinding
+roleRef:
+  kind: Role
+  name: payment-secrets-reader
 subjects:
   - kind: ServiceAccount
     name: payment-sa
     namespace: prod`,
    manualSteps: ['Create Role payment-secrets-reader scoped to resourceNames: [stripe-key, db-dsn].'],
    controls: [{ framework: 'NSA-CISA', id: 'RBAC' }],
    findingIds: ['kubescape:5e6f'],
    attackPathId: 'path-1',
    priority: 3,
    status: 'proposed',
    branch: 'sentinel/restrict-payment-sa',
    prTitle: 'Scope payment-sa to least-privilege Secret access',
    prBody: 'Proposed by K8s Sentinel. Severs the secret-access step of path-1.',
  },
  {
    id: 'fix-network-policy',
    playbookId: 'add-network-policy',
    title: 'Add default-deny NetworkPolicy for prod',
    severity: 'medium',
    kind: 'new-file',
    rationale:
      'Introduce a default-deny ingress/egress policy so only the API gateway can reach payment-api, shrinking the reachable surface.',
    path: 'k8s/prod/networkpolicy-default-deny.yaml',
    diff: `--- /dev/null
+++ b/k8s/prod/networkpolicy-default-deny.yaml
@@
+apiVersion: networking.k8s.io/v1
+kind: NetworkPolicy
+metadata:
+  name: default-deny
+  namespace: prod
+spec:
+  podSelector: {}
+  policyTypes: ["Ingress", "Egress"]`,
    manualSteps: ['Add explicit allow policies for the gateway → payment-api path.'],
    controls: [{ framework: 'CIS', id: 'CIS-5.3.2' }],
    findingIds: ['kubescape:9c0d'],
    attackPathId: 'path-1',
    priority: 4,
    status: 'proposed',
    branch: 'sentinel/prod-default-deny',
    prTitle: 'Add default-deny NetworkPolicy to prod',
    prBody: 'Proposed by K8s Sentinel.',
  },
];

export const DEMO_SNAPSHOT: RunSnapshot = {
  run: DEMO_RUN,
  findings: DEMO_FINDINGS,
  paths: DEMO_PATHS,
  fixes: DEMO_FIXES,
};
