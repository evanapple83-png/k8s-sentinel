# K8s Sentinel — Helm chart

Secure-by-default install of the K8s Sentinel control plane.

```bash
# Default (Claude engine; provide an API key secret)
kubectl create secret generic sentinel-anthropic --from-literal=ANTHROPIC_API_KEY=sk-...
helm install sentinel deploy/helm \
  --set engine.apiKeySecret=sentinel-anthropic

# Air-gapped (Hermes engine; zero egress) — Phase 4
helm install sentinel deploy/helm \
  --set engine.kind=hermes \
  --set egress.allow='{}' \
  --set sandbox.enabled=true --set sandbox.runtimeClassName=gvisor
```

## What ships locked down

- **Read-only RBAC** (`rbac.yaml`): `get`/`list`/`watch` only. There is no path
  in this chart to grant write — remediation is delivered as PRs, never applied
  in-cluster.
- **Egress allow-list** (`networkpolicy.yaml`): default-deny egress; DNS + API
  server + listed model hosts only. Set `egress.allow: []` for air-gap.
- **Hardened pods**: non-root, read-only root FS, all capabilities dropped,
  `RuntimeDefault` seccomp.
- **Sandbox**: scanner/execution plane runs under a gVisor/Kata `RuntimeClass`
  when `sandbox.enabled=true`.

## Verify locally

```bash
helm lint deploy/helm
helm template sentinel deploy/helm | kubectl apply --dry-run=client -f -
```
