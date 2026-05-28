# K8s Sentinel in-cluster agent — unified image (TS tunnel-client + ARGUS).
#
# The agent runs the TypeScript tunnel-client (`sentinel agent`) as PID 1. When
# a `scan` command arrives over the relay, the TS handler shells out to the
# Python ARGUS pipeline (`python3 -m argus.cli scan --in-cluster …`) which
# produces a v3 attack-graph report (CISA-KEV-aware). The report flows back
# over the same WSS tunnel as a snapshot frame.
#
# Read-only by construction:
#   * nonroot UID 65532
#   * the deployed RBAC (deploy/rbac.yaml) grants NO secrets verbs
#   * no scanner ever writes to the cluster; ARGUS never reads Secret .data
#
# Build context is the REPO ROOT (TS depends on @k8s-sentinel/* workspaces;
# Python depends on the argus/ package + requirements.txt). Published to ghcr.io
# by .github/workflows/publish-images.yml as ghcr.io/<owner>/k8s-sentinel.
#
# Pin scanner versions explicitly so re-builds are reproducible. Every bump is
# a supply-chain decision.
ARG NODE_VERSION=24-alpine
# Verified against the GitHub Releases API on 28 mei 2026. Trivy 0.55.x
# never shipped (the project jumped 0.26 → 0.69 → 0.70); 0.70.0 is the
# current stable. kube-bench 0.7.3 + Kubescape 3.0.20 are LTS-stable; bump
# them deliberately, not as a side-effect.
ARG TRIVY_VERSION=0.70.0
ARG KUBE_BENCH_VERSION=0.7.3
ARG KUBESCAPE_VERSION=3.0.20


# ---------------------------------------------------------------------------
# Stage 1: build the TS bundle. Node 24 because the store uses node:sqlite
# (stable/unflagged on Node ≥23, experimental on 22.x).
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS ts-build
RUN corepack enable
WORKDIR /repo
COPY . .
# Build the agent + only its workspace dependencies (turbo respects topo
# order), then produce a self-contained, prod-only bundle.  --legacy: pnpm
# v10+ refuses non-injected workspace deploys by default.
RUN pnpm install --frozen-lockfile=false \
 && pnpm exec turbo run build --filter=@k8s-sentinel/api... \
 && pnpm --filter @k8s-sentinel/api deploy --prod --legacy /app


# ---------------------------------------------------------------------------
# Stage 2: fetch + verify scanner binaries in a throwaway image. Keeps curl /
# tar out of the final runtime layer.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS scanners

ARG TARGETARCH
ARG TRIVY_VERSION
ARG KUBE_BENCH_VERSION
ARG KUBESCAPE_VERSION

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates tar \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /out

# Trivy — image / cluster CVE scanner.
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) trivy_arch="64bit" ;; \
      arm64) trivy_arch="ARM64" ;; \
      *)     echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" \
        -o trivy.tgz; \
    tar -xzf trivy.tgz trivy; \
    chmod +x trivy; \
    rm trivy.tgz; \
    ./trivy --version

# kube-bench — CIS benchmark on the cluster.
RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    curl -fsSL "https://github.com/aquasecurity/kube-bench/releases/download/v${KUBE_BENCH_VERSION}/kube-bench_${KUBE_BENCH_VERSION}_linux_${arch}.tar.gz" \
        -o kube-bench.tgz; \
    tar -xzf kube-bench.tgz kube-bench cfg; \
    chmod +x kube-bench; \
    rm kube-bench.tgz; \
    ./kube-bench version || ./kube-bench --help >/dev/null

# Kubescape — posture scan (failed-control → misconfig finding).
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) ks_asset="kubescape-ubuntu-latest" ;; \
      arm64) ks_asset="kubescape-ubuntu-22.04" ;; \
      *)     echo "unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/kubescape/kubescape/releases/download/v${KUBESCAPE_VERSION}/${ks_asset}" \
        -o kubescape; \
    chmod +x kubescape; \
    ./kubescape version || true


# ---------------------------------------------------------------------------
# Stage 3: runtime — alpine + Node + Python + scanners + both code trees.
# ---------------------------------------------------------------------------
FROM node:${NODE_VERSION} AS run

LABEL org.opencontainers.image.title="k8s-sentinel"
LABEL org.opencontainers.image.description="Read-only Kubernetes posture agent (TS tunnel-client + ARGUS attack-graph engine)"
LABEL org.opencontainers.image.source="https://github.com/evanapple83-png/k8s-sentinel"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV NODE_ENV=production \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/usr/local/bin:${PATH}"

# Python (for ARGUS) + ca-certificates (live CISA KEV fetch + registry HTTPS).
# py3-yaml from apk gives us a matching musl build without compiling C ext.
# kubernetes python client is pure Python — installs cleanly on musl via pip.
# --break-system-packages is safe inside a container dedicated to ARGUS.
RUN apk add --no-cache \
        python3 py3-pip py3-yaml ca-certificates \
 && pip install --no-cache-dir --break-system-packages --root-user-action=ignore kubernetes

# TS bundle into /app, Python ARGUS tree alongside it.
WORKDIR /app
COPY --from=ts-build /app /app
COPY argus/         /app/argus/
COPY requirements.txt /app/requirements.txt

# Scanner binaries.
COPY --from=scanners /out/trivy        /usr/local/bin/trivy
COPY --from=scanners /out/kube-bench   /usr/local/bin/kube-bench
COPY --from=scanners /out/cfg          /etc/kube-bench/cfg
COPY --from=scanners /out/kubescape    /usr/local/bin/kubescape

# ./data: sqlite + audit log mount (writable volume in k8s). ./argus-out:
# where ARGUS writes report.md / report.json; TS handler reads it back and
# ships it over the tunnel.
RUN mkdir -p /app/data /app/argus-out \
 && chown -R 65532:65532 /app/data /app/argus-out

# Build-time sanity: both stacks import + show their usage screens. Does NOT
# touch a cluster; only proves the image is wired correctly.
RUN node /app/dist/cli.js --help >/dev/null \
 && python3 -m argus.cli scan --help >/dev/null \
 && trivy --version >/dev/null \
 && kube-bench --help >/dev/null \
 && (kubescape version >/dev/null 2>&1 || true)

USER 65532:65532

# TS tunnel-client is PID 1 — long-lived, dials OUT to the relay, serves
# commands. ARGUS is invoked on-demand by the `scan` command handler.
CMD ["node", "/app/dist/cli.js", "agent"]
