import { sanitizeUntrusted, type Finding } from '@k8s-sentinel/core';
import { unifiedDiff } from './diff.js';

/**
 * Remediation playbook library (BUILD.md Feature 5).
 *
 * Each playbook recognizes a class of finding and produces a *reviewable* fix:
 * a representative manifest patch plus human steps. Nothing is ever applied —
 * the Author proposes, a human approves (§10). Builders are deterministic and
 * run offline. All untrusted scanner-derived text (names, images) is sanitized
 * before it enters a diff or rationale.
 */

export type RemediationKind = 'patch' | 'new-file' | 'manual';

export interface PlaybookFix {
  /** One-line, injection-safe explanation of the change. */
  rationale: string;
  /** Representative manifest path the change targets. */
  path: string;
  /** Unified diff. Empty for pure-manual playbooks. */
  diff: string;
  /** kubectl / manual fallback steps. */
  manualSteps: string[];
  kind: RemediationKind;
}

export interface Playbook {
  id: string;
  title: string;
  /** Higher wins when several playbooks match one finding. */
  priority: number;
  /** Control families this playbook helps satisfy (for the report rollup). */
  controls: string[];
  matches(finding: Finding): boolean;
  build(finding: Finding): PlaybookFix;
}

// ---- helpers ---------------------------------------------------------------

/** Sanitize a value for safe embedding in a diff/manifest/rationale. */
function safe(value: unknown, maxLength = 160): string {
  return sanitizeUntrusted(String(value ?? ''), { fence: false, maxLength }).trim();
}

function hasControl(f: Finding, id: string): boolean {
  return (f.controls ?? []).some((c) => c.id === id);
}

/** Strip a Trivy-style " (debian 12.1)" platform suffix and return repo/tag. */
function parseImage(image: string): { repo: string; tag: string; raw: string } {
  const cleaned = safe(image, 200).split(' ')[0] ?? '';
  const at = cleaned.split('@')[0] ?? cleaned; // drop any existing digest
  const lastColon = at.lastIndexOf(':');
  const hasTag = lastColon > at.lastIndexOf('/');
  return {
    repo: hasTag ? at.slice(0, lastColon) : at,
    tag: hasTag ? at.slice(lastColon + 1) : 'latest',
    raw: cleaned,
  };
}

function workloadName(f: Finding): string {
  if (f.resource.kind.toLowerCase() === 'image' && f.resource.image) {
    const { repo } = parseImage(f.resource.image);
    return safe(repo.split('/').pop() ?? repo, 80);
  }
  return safe(f.resource.name, 80);
}

function nsOf(f: Finding): string {
  return safe(f.resource.namespace ?? 'default', 60);
}

function manifestPath(f: Finding, kind: string, name = workloadName(f)): string {
  return `k8s/${nsOf(f)}/${kind.toLowerCase()}-${name}.yaml`;
}

function deployment(ns: string, name: string, image: string, extraContainer = ''): string {
  return [
    'apiVersion: apps/v1',
    'kind: Deployment',
    'metadata:',
    `  name: ${name}`,
    `  namespace: ${ns}`,
    'spec:',
    '  template:',
    '    spec:',
    '      containers:',
    `        - name: ${name}`,
    `          image: ${image}`,
    extraContainer,
  ]
    .filter((l) => l.length > 0)
    .join('\n');
}

// ---- playbooks -------------------------------------------------------------

const dropPrivileged: Playbook = {
  id: 'drop-privileged',
  title: 'Drop privileged execution and excess capabilities',
  priority: 90,
  controls: ['CIS-5.2.5', 'NSA-PodSecurity', 'MITRE-T1610'],
  matches: (f) =>
    f.ruleId === 'C-0057' ||
    hasControl(f, 'CIS-5.2.5') ||
    /privileged container|runs? as root|run-?as-?non-?root/i.test(f.title),
  build: (f) => {
    const ns = nsOf(f);
    const name = workloadName(f);
    const image = f.resource.image ? parseImage(f.resource.image).raw : `${name}:latest`;
    const before = deployment(ns, name, image);
    const after = deployment(
      ns,
      name,
      image,
      [
        '          securityContext:',
        '            privileged: false',
        '            allowPrivilegeEscalation: false',
        '            runAsNonRoot: true',
        '            runAsUser: 10001',
        '            capabilities:',
        '              drop: ["ALL"]',
      ].join('\n'),
    );
    const path = manifestPath(f, 'deployment', name);
    return {
      kind: 'patch',
      rationale: `Run ${ns}/${name} unprivileged: disable privileged mode, block privilege escalation, force a non-root UID, and drop all Linux capabilities.`,
      path,
      diff: unifiedDiff(path, before, after),
      manualSteps: [
        `Confirm the workload does not genuinely need host access (most do not).`,
        `Apply the securityContext above to every container in ${ns}/${name}.`,
        `Roll out and verify the pod still starts: kubectl -n ${ns} rollout status deploy/${name}`,
      ],
    };
  },
};

const readOnlyRootFs: Playbook = {
  id: 'read-only-root-fs',
  title: 'Make the container root filesystem read-only',
  priority: 50,
  controls: ['CIS-5.2.12', 'NSA-ImmutableFS'],
  matches: (f) =>
    f.ruleId === 'C-0017' ||
    hasControl(f, 'NSA-ImmutableFS') ||
    /immutable|read-?only root|readonlyrootfilesystem/i.test(f.title),
  build: (f) => {
    const ns = nsOf(f);
    const name = workloadName(f);
    const image = f.resource.image ? parseImage(f.resource.image).raw : `${name}:latest`;
    const before = deployment(ns, name, image);
    const after = deployment(
      ns,
      name,
      image,
      [
        '          securityContext:',
        '            readOnlyRootFilesystem: true',
        '          volumeMounts:',
        '            - name: tmp',
        '              mountPath: /tmp',
      ].join('\n'),
    );
    const path = manifestPath(f, 'deployment', name);
    return {
      kind: 'patch',
      rationale: `Set readOnlyRootFilesystem on ${ns}/${name} so an attacker who lands code execution cannot persist to the image filesystem. Mount an emptyDir for genuinely writable paths.`,
      path,
      diff: unifiedDiff(path, before, after),
      manualSteps: [
        `Identify writable paths the app needs and back them with emptyDir volumes.`,
        `Add an emptyDir volume "tmp" to spec.template.spec.volumes.`,
      ],
    };
  },
};

const restrictRbac: Playbook = {
  id: 'restrict-rbac',
  title: 'Scope down cluster-wide RBAC to least privilege',
  priority: 85,
  controls: ['CIS-5.2.6', 'NSA-PrivEsc', 'MITRE-T1611'],
  matches: (f) =>
    f.ruleId === 'C-0186' ||
    hasControl(f, 'T1611') ||
    /cluster-?takeover|cluster-?admin|over-?privileg|wildcard|cluster role/i.test(f.title),
  build: (f) => {
    const ns = nsOf(f);
    const name = workloadName(f);
    const sa = `${name.replace(/-(api|svc|service|app)$/, '')}-sa`;
    const before = [
      'apiVersion: rbac.authorization.k8s.io/v1',
      'kind: ClusterRoleBinding',
      'metadata:',
      `  name: ${name}-admin`,
      'roleRef:',
      '  kind: ClusterRole',
      '  name: cluster-admin',
      '  apiGroup: rbac.authorization.k8s.io',
      'subjects:',
      '  - kind: ServiceAccount',
      `    name: ${sa}`,
      `    namespace: ${ns}`,
    ].join('\n');
    const after = [
      '# Replaced the cluster-admin binding with a namespaced, least-privilege Role.',
      'apiVersion: rbac.authorization.k8s.io/v1',
      'kind: Role',
      'metadata:',
      `  name: ${name}`,
      `  namespace: ${ns}`,
      'rules:',
      '  - apiGroups: [""]',
      '    resources: ["configmaps"]',
      '    verbs: ["get", "list", "watch"]',
      '---',
      'apiVersion: rbac.authorization.k8s.io/v1',
      'kind: RoleBinding',
      'metadata:',
      `  name: ${name}`,
      `  namespace: ${ns}`,
      'roleRef:',
      '  kind: Role',
      `  name: ${name}`,
      '  apiGroup: rbac.authorization.k8s.io',
      'subjects:',
      '  - kind: ServiceAccount',
      `    name: ${sa}`,
      `    namespace: ${ns}`,
    ].join('\n');
    const path = manifestPath(f, 'rbac', name);
    return {
      kind: 'patch',
      rationale: `Remove the cluster-admin binding for service account ${sa} and replace it with a namespaced Role granting only the verbs ${ns}/${name} actually uses — this severs the "compromise pod → take over cluster" step.`,
      path,
      diff: unifiedDiff(path, before, after),
      manualSteps: [
        `Audit what API calls ${ns}/${name} makes (kubectl can't infer this — check the app).`,
        `Grant only those verbs/resources in the Role; never reuse cluster-admin for workloads.`,
        `Delete the old ClusterRoleBinding once the scoped Role is verified.`,
      ],
    };
  },
};

const pinImage: Playbook = {
  id: 'pin-image',
  title: 'Rebuild on a patched base image and pin by digest',
  priority: 80,
  controls: ['SOC2-CC7.1', 'MITRE-T1190'],
  matches: (f) => f.source === 'trivy',
  build: (f) => {
    const ns = nsOf(f);
    const name = workloadName(f);
    const { raw, repo, tag } = f.resource.image
      ? parseImage(f.resource.image)
      : { raw: `${name}:latest`, repo: name, tag: 'latest' };
    const cve = safe(f.ruleId, 40);
    const before = deployment(ns, name, raw);
    const after = deployment(
      ns,
      name,
      `${repo}:${tag}@sha256:<digest-after-rebuild>  # rebuilt on patched base — fixes ${cve}`,
    );
    const path = manifestPath(f, 'deployment', name);
    return {
      kind: 'patch',
      rationale: `${cve} is exploitable in ${raw}. Rebuild on a patched base image and pin the deployment to the new digest so the fixed layer can't be silently replaced.`,
      path,
      diff: unifiedDiff(path, before, after),
      manualSteps: [
        `Update the base image / package to the version that fixes ${cve}.`,
        `Rebuild and push; capture the new digest: docker buildx imagetools inspect ${repo}:${tag}`,
        `Pin the deployment to ${repo}:${tag}@sha256:<digest> and roll out.`,
      ],
    };
  },
};

const addNetworkPolicy: Playbook = {
  id: 'add-network-policy',
  title: 'Add a default-deny NetworkPolicy',
  priority: 70,
  controls: ['NSA-NetworkExposure', 'NSA-NetworkSeparation', 'SOC2-CC6.6'],
  matches: (f) =>
    f.ruleId === 'C-0256' ||
    f.ruleId === 'C-0260' ||
    hasControl(f, 'NSA-NetworkExposure') ||
    hasControl(f, 'NSA-NetworkSeparation') ||
    /exposure to internet|network (separation|polic)|internet[- ]exposed/i.test(f.title),
  build: (f) => {
    const ns = nsOf(f);
    const name = workloadName(f);
    const app = name.replace(/-(svc|service)$/, '');
    const after = [
      'apiVersion: networking.k8s.io/v1',
      'kind: NetworkPolicy',
      'metadata:',
      `  name: ${app}-default-deny`,
      `  namespace: ${ns}`,
      'spec:',
      '  podSelector:',
      '    matchLabels:',
      `      app: ${app}`,
      '  policyTypes: [Ingress, Egress]',
      '  ingress:',
      '    - from:',
      '        - podSelector:',
      '            matchLabels:',
      '              app: api-gateway',
      '      ports:',
      '        - protocol: TCP',
      '          port: 8080',
      '  egress:',
      '    - to:',
      '        - namespaceSelector: {}',
      '      ports:',
      '        - protocol: UDP',
      '          port: 53',
      '        - protocol: TCP',
      '          port: 53',
    ].join('\n');
    const path = `k8s/${ns}/networkpolicy-${app}.yaml`;
    return {
      kind: 'new-file',
      rationale: `No NetworkPolicy selects ${ns}/${name}, so any pod (or the internet, via the Service) can reach it. Add a default-deny policy that only admits the intended caller and DNS egress.`,
      path,
      diff: unifiedDiff(path, '', after),
      manualSteps: [
        `Confirm which clients legitimately call ${app} and tighten the ingress "from" selector.`,
        `Ensure your CNI enforces NetworkPolicy (Calico/Cilium); the default kubenet does not.`,
      ],
    };
  },
};

const nodeHardening: Playbook = {
  id: 'node-hardening',
  title: 'Harden the control-plane / kubelet configuration',
  priority: 40,
  controls: ['CIS-1.x', 'CIS-4.x'],
  matches: (f) => f.source === 'kube-bench',
  build: (f) => {
    const rule = safe(f.ruleId, 40);
    const node = safe(f.resource.name, 60);
    return {
      kind: 'manual',
      rationale: `CIS benchmark ${rule} failed on node ${node}. Control-plane and kubelet flags are host-level config, not a workload manifest — apply the change on the node and re-run kube-bench.`,
      path: `nodes/${node}/kube-bench-${rule}.md`,
      diff: '',
      manualSteps: [
        `Locate the relevant component manifest on ${node} (e.g. /etc/kubernetes/manifests/kube-apiserver.yaml or the kubelet config).`,
        `Set the flag/field called out by CIS ${rule} to its compliant value.`,
        `Restart the affected component and re-run: kube-bench run --targets node`,
      ],
    };
  },
};

const runtimeDetection: Playbook = {
  id: 'runtime-detection',
  title: 'Investigate and contain the runtime detection',
  priority: 30,
  controls: ['SOC2-CC7.2', 'MITRE-TA0002'],
  matches: (f) => f.source === 'falco',
  build: (f) => {
    const ns = nsOf(f);
    const pod = safe(f.resource.name, 80);
    const what = safe(f.title, 120);
    return {
      kind: 'manual',
      rationale: `Falco observed "${what}" in ${ns}/${pod} at runtime. This is behaviour, not config — triage it, then prevent recurrence by hardening the workload (see related drop-privileged / read-only-root-fs fixes).`,
      path: `runbooks/${ns}/${pod}.md`,
      diff: '',
      manualSteps: [
        `Triage now: kubectl -n ${ns} logs ${pod} and inspect the process tree for unexpected shells/binaries.`,
        `If interactive access is confirmed, rotate any credentials the pod could read and cordon the node.`,
        `Prevent recurrence: enforce a read-only root FS and a restrictive seccomp profile on the workload.`,
      ],
    };
  },
};

/** Registry, ordered by descending priority (highest-value fix first). */
export const PLAYBOOKS: readonly Playbook[] = [
  dropPrivileged,
  restrictRbac,
  pinImage,
  addNetworkPolicy,
  readOnlyRootFs,
  nodeHardening,
  runtimeDetection,
].sort((a, b) => b.priority - a.priority);

/** The highest-priority playbook that matches a finding, if any. */
export function findPlaybook(finding: Finding): Playbook | undefined {
  return PLAYBOOKS.find((p) => p.matches(finding));
}
