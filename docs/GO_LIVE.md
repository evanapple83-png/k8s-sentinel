# Going live — test K8s Sentinel + ARGUS v3 against a real cluster

End-to-end checklist for the `feat/argus-go-live` branch. Everything above
"open questions" has been built, typechecked and unit-tested green; what
remains is the work that needs Docker / Helm / a Kubernetes cluster (none of
which were available where the build ran).

## 1. Verify the unified ARGUS image builds

The Dockerfile bakes TS tunnel-client + Python ARGUS + Trivy/kube-bench/
Kubescape into one image. Build from the repo root (build context = repo
root because of the workspace deps):

```bash
docker build -f apps/api/Dockerfile -t k8s-sentinel:argus-v3 .
```

What to expect: ~7 min cold (downloads scanner binaries in stage 2), final
image ~800 MB. Failures here are usually:

- **`pnpm deploy --legacy` error** → pnpm v11 incompat; the Dockerfile pins
  `--legacy` to work around it.
- **scanner SHA mismatch** → bump the pinned `TRIVY_VERSION` / `KUBE_BENCH_VERSION`
  / `KUBESCAPE_VERSION` ARGs at the top of the Dockerfile.

## 2. Publish to GHCR

```bash
echo $GHCR_TOKEN | docker login ghcr.io -u evanapple83-png --password-stdin
docker tag k8s-sentinel:argus-v3 ghcr.io/evanapple83-png/k8s-sentinel:0.2.0-argus-v3
docker push ghcr.io/evanapple83-png/k8s-sentinel:0.2.0-argus-v3
```

Or just push to `main` and let the `.github/workflows/publish-images.yml`
workflow do it — the workflow already builds from `apps/api/Dockerfile`.

## 3. Smoke-test on a throwaway kind cluster

```bash
# Prereqs: kind, kubectl, python3 (with the `kubernetes` + `PyYAML` Python
# deps from requirements.txt), and trivy on PATH.
pip install -r requirements.txt

scripts/smoke.sh                # one-shot: create kind, seed workloads, scan
scripts/smoke.sh --build        # …and docker build + kind load first
scripts/smoke.sh --keep         # keep the cluster around for poking
```

DoD §6 the script enforces:

1. `deploy/rbac.yaml` applies cleanly.
2. The vulnerable + benign seed workloads roll out.
3. `argus scan` succeeds using ONLY the read-only ServiceAccount.
4. ≥1 attack path in the report; vulnerable workload outranks benign.
5. Secret `.data` never appears anywhere in the report.

If smoke passes, the unified image + Helm RBAC posture are live-cluster-ready.

## 4. Apply the Supabase migration

The control-plane needs migration `20260528000005_argus_v3.sql` before it can
ingest v3 PostureSnapshots:

```bash
# Locally with supabase CLI (if you use it)
supabase db push

# Or paste the migration into the Supabase SQL editor for the
# fmdrkydbihmmemddqdvp project and run it once.
```

After this, the `finding` table gets `cve / kev / ransomware / epss / ssvc /
confidence / exposure / reaches` columns, `run` gets `intel_*` columns, and a
new `choke_point` table appears with RLS enabled.

## 5. Bump the relay + control-plane deploys

The relay-protocol changes (new optional v3 wire fields) are backward-
compatible, but both ends need the new schema deployed for the typed channel
to actually flow. In practice that means:

```bash
# Vercel (control-plane) — branch deploy will pick up the schema changes.
git push origin feat/argus-go-live
# When merged to main, the production deploy upgrades.

# Fly (relay) — stateless WS forwarder; no schema, no migration. Optional
# bump.
fly deploy -a k8s-sentinel-relay
```

## 6. Onboard a real cluster (hybrid mode)

Per `deploy/helm/README.md`:

```bash
# 1. In the hosted UI (control-plane-azure.vercel.app):
#    Settings → Connect a cluster → Mint install token.
kubectl create namespace sentinel
kubectl -n sentinel create secret generic sentinel-install \
  --from-literal=SENTINEL_INSTALL_TOKEN=sit-XXXXXXXX

# 2. Install. The Helm chart now points at the ARGUS v3 image by default.
helm install sentinel deploy/helm \
  --namespace sentinel \
  --set mode=hybrid \
  --set relay.url=wss://k8s-sentinel-relay.fly.dev \
  --set relay.installTokenSecret=sentinel-install

# 3. Watch the agent register:
kubectl -n sentinel logs -l app.kubernetes.io/component=control-plane -f

# 4. Trigger a scan from the dashboard. First scan: 30–90 s on a small
#    cluster. Watch the snapshot land in the Overview screen — IntelBanner
#    shows the catalog version, ChokePointsPanel surfaces "apply this and
#    N paths collapse".
```

### Optional — GitOps accepted-risk waivers (Fase 6)

```bash
# Each .md file under .sentinel/accepted-risks/ is one waiver.
# Format: see argus/accepted_risks.py — YAML frontmatter with id, match,
# expires, owner, approver, optional compensating_controls.
kubectl -n sentinel create configmap sentinel-accepted-risks \
  --from-file=.sentinel/accepted-risks/

helm upgrade sentinel deploy/helm \
  --reuse-values \
  --set argus.acceptedRisks.enabled=true \
  --set argus.acceptedRisks.configMapName=sentinel-accepted-risks
```

The Overview header shows waiver activity in the run summary line: `… · N waived,
M refused, K auto-reopened`.

## Open follow-ups

- **Fase 6 typed waivers**: today AR counts are smuggled into the run.summary
  string. A future change should add a typed `snapshot.waivers` field
  (accepted[], refused[], auto-reopened[]) plus a dedicated dashboard panel
  with the waiver IDs + owners + expiry. Migration prep: extend
  `apps/control-plane/lib/wire.ts` mirror first, then relay-protocol, then
  argus.ts mapper.
- **Choke-points dashboard panel deduplication**: today the agent mirrors
  choke-points into BOTH `snapshot.chokePoints` (typed, v3 source of truth)
  AND `snapshot.remediations` (legacy `Fixes` screen). Once the v3 panel
  ships and operators are off the legacy view, drop the mirror in
  `mapChokePointsToRemediations()` and the wire frame shrinks.
- **Helm chart in CI**: add `helm lint` + `helm template … | kubectl
  apply --dry-run` to the test workflow so chart regressions fail PRs.
