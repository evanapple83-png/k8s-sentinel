# K8s Sentinel in-cluster agent — container image.
#
# Runs `sentinel agent`: the read-only agent that dials OUT to the relay (hybrid
# mode) or serves locally (cluster-local). Build context is the REPO ROOT (the
# agent depends on many @k8s-sentinel/* workspace packages). Published to ghcr.io
# by .github/workflows/publish-images.yml.
#
# Node 24: the store uses `node:sqlite`, which is stable/unflagged on Node ≥ 23
# (experimental + flagged on 22.x), so we pin 24 to match local dev.

FROM node:24-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY . .
# Build the agent + only its workspace dependencies (turbo respects topo order),
# then produce a self-contained, prod-only bundle. --legacy: pnpm v10+ refuses
# non-injected workspace deploys by default.
RUN pnpm install --frozen-lockfile=false \
 && pnpm exec turbo run build --filter=@k8s-sentinel/api... \
 && pnpm --filter @k8s-sentinel/api deploy --prod --legacy /app

FROM node:24-alpine AS run
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app /app
# ./data (sqlite + audit log) is provided by a writable volume in k8s. Create it
# for local runs and hand it to the non-root user.
RUN mkdir -p /app/data && chown -R 65532:65532 /app/data
USER 65532:65532
CMD ["node", "dist/cli.js", "agent"]
