# K8s Sentinel — Helm chart

Secure-by-default install of the K8s Sentinel control plane.

```bash
# Default (Claude engine; provide an API key secret)
kubectl create secret generic sentinel-anthropic --from-literal=ANTHROPIC_API_KEY=sk-...
helm install sentinel deploy/helm \
  --set engine.apiKeySecret=sentinel-anthropic

# Air-gapped (Hermes engine; ZERO external egress) — Phase 4.
# Selecting engine.kind=hermes alone drops all public egress (see below).
helm install sentinel deploy/helm \
  --set engine.kind=hermes \
  --set engine.hermes.baseUrl=http://hermes:8080/v1 \
  --set sandbox.enabled=true --set sandbox.runtimeClassName=gvisor
```

Both are **one command**. After install the `NOTES` print how to reach the API
(`kubectl port-forward`) and which posture is active.

## What ships locked down

- **Read-only RBAC** (`rbac.yaml`): `get`/`list`/`watch` only. There is no path
  in this chart to grant write — remediation is delivered as PRs, never applied
  in-cluster.
- **Egress allow-list** (`networkpolicy.yaml`): default-deny egress; DNS +
  in-cluster/private CIDRs always, plus public 443 in Claude mode. Setting
  `engine.kind=hermes` removes the public rule entirely → zero external calls.
- **Hardened pods**: non-root, read-only root FS, all capabilities dropped,
  `RuntimeDefault` seccomp.
- **Sandbox**: scanner/execution plane runs under a gVisor/Kata `RuntimeClass`
  when `sandbox.enabled=true`.

## Verify locally

```bash
helm lint deploy/helm
helm template sentinel deploy/helm | kubectl apply --dry-run=client -f -
```
