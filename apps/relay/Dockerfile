# K8s Sentinel relay — container image (deploys to Fly.io).
#
# Build context is the REPO ROOT (the relay depends on the @k8s-sentinel/
# relay-protocol workspace package). From the repo root:
#   fly deploy --config apps/relay/fly.toml --dockerfile apps/relay/Dockerfile
#
# Stage 1 builds the protocol + relay and produces a self-contained, prod-only
# bundle with `pnpm deploy`. Stage 2 runs it as a non-root user.

FROM node:22-alpine AS build
RUN corepack enable
WORKDIR /repo
COPY . .
RUN pnpm install --frozen-lockfile=false \
 && pnpm --filter @k8s-sentinel/relay-protocol build \
 && pnpm --filter @k8s-sentinel/relay build \
 && pnpm --filter @k8s-sentinel/relay deploy --prod --legacy /app

FROM node:22-alpine AS run
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app /app
USER 65532:65532
EXPOSE 8080
CMD ["node", "dist/server.js"]
