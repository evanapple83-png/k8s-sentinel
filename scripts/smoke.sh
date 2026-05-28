#!/usr/bin/env bash
# scripts/smoke.sh — end-to-end ARGUS smoke test on a throwaway kind cluster.
#
# What it proves (DoD §6 — Phase 5):
#   1. deploy/rbac.yaml applies cleanly to a real API server.
#   2. The seed workloads roll out (vulnerable-web exposed, benign-internal
#      internal-only with a deny-external NetworkPolicy).
#   3. ``argus scan`` succeeds using ONLY the ``argus`` ServiceAccount's
#      read-only token — proving the shipped RBAC is sufficient.
#   4. The report contains >= 1 attack path and the vulnerable workload
#      outranks the benign one.
#   5. No Secret ``.data`` appears anywhere in the report.
#
# Prerequisites: kind, kubectl, python3, trivy. (Trivy is required because
# the attack-path assertion needs real CVE rows on the vulnerable image.)
#
# Usage:
#   scripts/smoke.sh                        # build nothing, run from host
#   scripts/smoke.sh --build                # docker build + kind load too
#   scripts/smoke.sh --keep                 # don't delete the cluster on exit
#   CLUSTER_NAME=foo scripts/smoke.sh       # override cluster name
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-argus-smoke}"
KEEP=0
BUILD=0

for arg in "$@"; do
  case "$arg" in
    --keep)  KEEP=1 ;;
    --build) BUILD=1 ;;
    --help|-h)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *)
      printf 'unknown flag: %s\n' "$arg" >&2
      exit 2
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE_DIR="$(mktemp -d -t argus-smoke.XXXXXX)"
KUBECONFIG_OUT="${SMOKE_DIR}/kubeconfig-argus.yaml"
OUT_DIR="${SMOKE_DIR}/out"

log() { printf '[smoke] %s\n' "$*" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || { log "missing prerequisite: $1"; exit 127; }; }

need kind
need kubectl
need python3
need trivy

cleanup() {
  rc=$?
  if [[ "$KEEP" -eq 1 ]]; then
    log "keeping cluster '$CLUSTER_NAME' and outputs in $SMOKE_DIR"
  else
    log "tearing down cluster '$CLUSTER_NAME'"
    kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
    rm -rf "$SMOKE_DIR"
  fi
  exit "$rc"
}
trap cleanup EXIT

# ----------------------------------------------------------------------------
# 1. kind cluster (idempotent)
# ----------------------------------------------------------------------------
log "creating kind cluster '$CLUSTER_NAME' (idempotent)"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  kind create cluster --name "$CLUSTER_NAME" --wait 120s
else
  log "  cluster already exists, reusing"
fi
KCTX="kind-${CLUSTER_NAME}"

# ----------------------------------------------------------------------------
# 2. (optional) docker build + kind load
# ----------------------------------------------------------------------------
if [[ "$BUILD" -eq 1 ]]; then
  need docker
  log "building argus:smoke image from $REPO_ROOT"
  docker build -t argus:smoke "$REPO_ROOT"
  log "kind-loading argus:smoke"
  kind load docker-image argus:smoke --name "$CLUSTER_NAME"
fi

# ----------------------------------------------------------------------------
# 3. apply RBAC + seed workloads
# ----------------------------------------------------------------------------
log "applying read-only RBAC"
kubectl --context "$KCTX" apply -f "$REPO_ROOT/deploy/rbac.yaml" >/dev/null

log "applying seed workloads"
kubectl --context "$KCTX" apply -f "$REPO_ROOT/test/vulnerable-workloads.yaml" >/dev/null

log "waiting for rollouts"
kubectl --context "$KCTX" -n argus-smoke wait --for=condition=Available \
    deploy/vulnerable-web deploy/benign-internal --timeout=180s

# ----------------------------------------------------------------------------
# 4. mint a kubeconfig that uses the argus SA token + scan with it
# ----------------------------------------------------------------------------
log "minting argus SA token + writing scoped kubeconfig"
TOKEN="$(kubectl --context "$KCTX" -n argus-system create token argus --duration=1h)"
SERVER="$(kubectl --context "$KCTX" config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
CA_DATA="$(kubectl --context "$KCTX" config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"

if [[ -z "$CA_DATA" ]]; then
  log "kind kubeconfig has no embedded CA — refusing to run with insecure config"
  exit 1
fi

cat > "$KUBECONFIG_OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: ${CLUSTER_NAME}
    cluster:
      server: ${SERVER}
      certificate-authority-data: ${CA_DATA}
users:
  - name: argus
    user:
      token: ${TOKEN}
contexts:
  - name: argus
    context:
      cluster: ${CLUSTER_NAME}
      user: argus
current-context: argus
EOF
chmod 600 "$KUBECONFIG_OUT"

log "running argus scan as the argus SA (read-only)"
mkdir -p "$OUT_DIR"
# Trivy is sufficient for the attack-path assertion; kube-bench + Kubescape
# are out of scope for a host-driven smoke (they would need their own
# in-cluster Job to function meaningfully).
PYTHONPATH="$REPO_ROOT" python3 -m argus.cli scan \
  --kubeconfig "$KUBECONFIG_OUT" --context argus \
  --cluster-name "$CLUSTER_NAME" \
  --out "$OUT_DIR" \
  --images-only \
  --quiet

REPORT_JSON="$OUT_DIR/report.json"
REPORT_MD="$OUT_DIR/report.md"
[[ -f "$REPORT_JSON" ]] || { log "report.json missing"; exit 1; }
[[ -f "$REPORT_MD"   ]] || { log "report.md missing";   exit 1; }

# ----------------------------------------------------------------------------
# 5. assertions
# ----------------------------------------------------------------------------
log "validating report assertions"
PYTHONPATH="$REPO_ROOT" REPORT_JSON="$REPORT_JSON" python3 - <<'PY'
import json, os, sys

path = os.environ["REPORT_JSON"]
with open(path) as f:
    r = json.load(f)

# (a) >= 1 attack path
paths = r.get("attackPaths") or []
assert paths, f"FAIL: expected >=1 attack path, got 0\nfull report at {path}"

# (b) the attack path is anchored on the vulnerable workload
ap_targets = []
for p in paths:
    for step in p.get("steps") or []:
        if "argus-smoke/vulnerable-web" in step:
            ap_targets.append(p["id"])
            break
assert ap_targets, f"FAIL: no attack path mentions argus-smoke/vulnerable-web — got {paths}"

# (c) vulnerable workload outranks benign on top finding score
def top_score(target):
    return max((f["adjusted"] for f in r["findings"] if f["target"] == target), default=0)
vuln_top   = top_score("argus-smoke/vulnerable-web")
benign_top = top_score("argus-smoke/benign-internal")
assert vuln_top > benign_top, (
    f"FAIL: vulnerable workload did not outrank benign — vuln={vuln_top} benign={benign_top}"
)

# (d) no secret data leaked
blob = json.dumps(r)
assert '"data":' not in blob, "FAIL: report contains a JSON 'data' key"
assert 'not-a-real-password' not in blob, "FAIL: report contains the seed Secret value"

# (e) inventory recorded the vulnerable workload as publicly exposed
# (implicit — only an exposed workload can anchor an attack path; assertion
# (b) already covers it, but we double-check the score is high.)
assert vuln_top >= 58, f"FAIL: vulnerable workload top score {vuln_top} unexpectedly low"

print(f"OK riskScore={r['riskScore']} paths={len(paths)} "
      f"vuln_top={vuln_top} benign_top={benign_top}")
PY

log "smoke test passed"
log "  report.md   : $REPORT_MD"
log "  report.json : $REPORT_JSON"
