#!/usr/bin/env bash
# K8s Sentinel — mTLS CA helper for the relay (Phase 5, hybrid mode).
#
# The relay authenticates agents by a per-cluster mTLS CLIENT certificate whose
# Common Name (CN) is the clusterId (docs/DATA-BOUNDARY.md). This script creates
# the CA and issues those client certs. Keep ca.key OFFLINE/secret; only ca.crt
# goes to the relay (RELAY_CLIENT_CA).
#
# Usage:
#   deploy/relay/relay-ca.sh init                         # one-time: make the CA
#   deploy/relay/relay-ca.sh issue <clusterId> [out-dir]  # issue a client cert
#
# Output of `issue`: <out>/tls.crt, <out>/tls.key, <out>/ca.crt — ready to load
# into a Kubernetes Secret consumed by Helm (relay.clientCertSecret). The printed
# kubectl command does exactly that.
set -euo pipefail

DIR="${RELAY_CA_DIR:-./relay-ca}"
DAYS_CA="${RELAY_CA_DAYS:-3650}"
DAYS_CERT="${RELAY_CERT_DAYS:-365}"

init() {
  mkdir -p "$DIR"
  if [[ -f "$DIR/ca.crt" ]]; then
    echo "CA already exists at $DIR/ca.crt — refusing to overwrite." >&2
    exit 1
  fi
  openssl genrsa -out "$DIR/ca.key" 4096
  openssl req -x509 -new -nodes -key "$DIR/ca.key" -sha256 -days "$DAYS_CA" \
    -subj "/CN=K8s Sentinel Relay CA/O=K8s Sentinel" -out "$DIR/ca.crt"
  chmod 600 "$DIR/ca.key"
  echo "✓ CA created:"
  echo "    $DIR/ca.crt   → set on the relay as RELAY_CLIENT_CA"
  echo "    $DIR/ca.key   → KEEP SECRET / OFFLINE (signs client certs)"
}

issue() {
  local cluster_id="${1:?usage: issue <clusterId> [out-dir]}"
  local out="${2:-./relay-cert-$cluster_id}"
  if [[ ! -f "$DIR/ca.crt" || ! -f "$DIR/ca.key" ]]; then
    echo "No CA found in $DIR — run 'init' first." >&2
    exit 1
  fi
  mkdir -p "$out"
  # CN = clusterId: the relay reads it as the bound cluster identity.
  openssl genrsa -out "$out/tls.key" 2048
  openssl req -new -key "$out/tls.key" -subj "/CN=$cluster_id/O=K8s Sentinel Agent" -out "$out/tls.csr"
  openssl x509 -req -in "$out/tls.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" \
    -CAcreateserial -days "$DAYS_CERT" -sha256 -out "$out/tls.crt"
  cp "$DIR/ca.crt" "$out/ca.crt"
  rm -f "$out/tls.csr"
  chmod 600 "$out/tls.key"

  echo "✓ Issued client cert for clusterId=$cluster_id → $out/{tls.crt,tls.key,ca.crt}"
  echo
  echo "Load it into the agent's cluster as a Secret, then install in hybrid mode:"
  echo "  kubectl -n sentinel create secret generic sentinel-relay-cert \\"
  echo "    --from-file=tls.crt=$out/tls.crt \\"
  echo "    --from-file=tls.key=$out/tls.key \\"
  echo "    --from-file=ca.crt=$out/ca.crt"
  echo "  helm install sentinel oci://ghcr.io/your-org/k8s-sentinel \\"
  echo "    -n sentinel --set mode=hybrid \\"
  echo "    --set relay.url=wss://relay.k8s-sentinel.example \\"
  echo "    --set relay.clientCertSecret=sentinel-relay-cert"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  init)  init "$@" ;;
  issue) issue "$@" ;;
  *) echo "usage: $0 {init | issue <clusterId> [out-dir]}" >&2; exit 1 ;;
esac
