# K8s Sentinel — Helm chart

Secure-by-default install of the K8s Sentinel agent + control plane.

> v0.2.0 ships the **ARGUS v3 attack-graph engine** by default (CISA-KEV-aware,
> SSVC-tiered) bundled with Trivy + kube-bench + Kubescape in a single image.

## Two modes

### Hybrid (recommended) — agent in your cluster, dashboard hosted by us

The agent dials OUT to our hosted relay over a single durable WSS connection
— no inbound port, no public IP, no kubeconfig leaving your cluster. The web
UI lives at `control-plane-azure.vercel.app`.

```bash
# 1. In the hosted UI: Settings → Connect a cluster → Mint install token.
#    You get a single-use token good for 15 minutes.
kubectl create namespace sentinel
kubectl -n sentinel create secret generic sentinel-install \
  --from-literal=SENTINEL_INSTALL_TOKEN=sit-XXXXXXXX

# 2. Install. Helm pulls the unified ARGUS v3 image from ghcr.
helm install sentinel deploy/helm \
  --namespace sentinel \
  --set mode=hybrid \
  --set relay.url=wss://k8s-sentinel-relay.fly.dev \
  --set relay.installTokenSecret=sentinel-install

# 3. Watch the pod register, then trigger a scan from the dashboard.
kubectl -n sentinel logs -l app.kubernetes.io/component=control-plane -f
```

The first scan typically completes in 30–90 s on a small cluster and pushes a
PostureSnapshot (findings + attack paths + choke-points + KEV/EPSS/SSVC
metadata) back through the relay. The UI's Overview screen surfaces the
choke-points first ("apply this and N paths collapse").

### Cluster-local — full product + dashboard inside the cluster

For air-gap / regulated environments. Pair with the **Hermes** engine to drop
all public egress.

```bash
# Default (Claude engine; needs ANTHROPIC_API_KEY)
kubectl create secret generic sentinel-anthropic --from-literal=ANTHROPIC_API_KEY=sk-...
helm install sentinel deploy/helm \
  --set engine.apiKeySecret=sentinel-anthropic

# Air-gapped — zero external calls.
helm install sentinel deploy/helm \
  --set engine.kind=hermes \
  --set engine.hermes.baseUrl=http://hermes:8080/v1 \
  --set sandbox.enabled=true --set sandbox.runtimeClassName=gvisor
```

After install the `NOTES` print how to reach the API (`kubectl port-forward`).

## ARGUS v3 knobs (values.yaml › `argus.*`)

| Key                                 | Default     | What it does                                        |
| ----------------------------------- | ----------- | --------------------------------------------------- |
| `argus.scanner`                     | `argus`     | `argus` (v3 attack-graph) \| `builtin` (legacy TS)  |
| `argus.imagesOnly`                  | `false`     | Skip kube-bench + Kubescape (image CVEs only)       |
| `argus.noNetwork`                   | `false`     | Use cached CISA-KEV + override file (no live fetch) |
| `argus.acceptedRisks.enabled`       | `false`     | Mount waiver ConfigMap at /etc/sentinel/accepted-risks |
| `argus.acceptedRisks.configMapName` | `""`        | Name of the ConfigMap holding `*.md` waiver files   |

### GitOps-style accepted-risk waivers

ARGUS reads `*.md` waiver files from a directory and suppresses matching
findings (with auto-reopen when the named control fails again). Store them
alongside your platform repo so the waivers live in Git, not the UI:

```bash
# Each .md file is a single waiver. See argus/README.md for the format.
kubectl -n sentinel create configmap sentinel-accepted-risks \
  --from-file=.sentinel/accepted-risks/

helm upgrade sentinel deploy/helm \
  --reuse-values \
  --set argus.acceptedRisks.enabled=true \
  --set argus.acceptedRisks.configMapName=sentinel-accepted-risks
```

The dashboard surfaces waived findings with a "waived" banner so suppression
is auditable, not hidden.

## What ships locked down

- **Read-only RBAC** (`rbac.yaml`): `get`/`list`/`watch` only. **NO secrets
  verbs anywhere** — ARGUS derives Secret reachability from RBAC + pod volume
  mounts and never reads `.data`. There is no path in this chart to grant
  write; remediation is delivered as PR bundles for human approval, never
  applied in-cluster.
- **Egress allow-list** (`networkpolicy.yaml`): default-deny egress; DNS +
  in-cluster/private CIDRs always, plus public 443 in Claude mode. Setting
  `engine.kind=hermes` removes the public rule entirely → zero external calls.
- **Hardened pods**: non-root (UID 65532), read-only root FS, all capabilities
  dropped, `RuntimeDefault` seccomp.
- **Sandbox**: scanner/execution plane runs under a gVisor/Kata `RuntimeClass`
  when `sandbox.enabled=true`.

## Verify locally

```bash
helm lint deploy/helm
helm template sentinel deploy/helm \
  --set mode=hybrid --set relay.url=wss://x --set relay.installToken=sit-test \
  | kubectl apply --dry-run=client -f -
```

For a full end-to-end run on a throwaway cluster (kind + vulnerable workloads),
see `scripts/smoke.sh`.
