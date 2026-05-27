# K8s Sentinel

> Autonomous, **self-hosted** AI security agent for Kubernetes. Orchestrates
> best-of-breed open-source scanners, correlates their findings into **ranked
> attack paths**, and ships audit-ready reports — read-only by default.

See [`docs/BUILD.md`](docs/BUILD.md) for the full spec and [`CLAUDE.md`](CLAUDE.md)
for the working contract.

## Quick start

```bash
pnpm install
pnpm build

# Phase 0 smoke test — runs a trivial agent and writes an audit entry.
# Falls back to the offline Mock engine when no ANTHROPIC_API_KEY is set.
pnpm --filter @k8s-sentinel/api phase0
```

Copy `.env.example` → `.env` and set `ANTHROPIC_API_KEY` to use the real Claude
Agent SDK engine. Leave it unset to run fully offline against fixtures.

## Architecture

Three specialized agents behind a thin orchestrator, over a swappable engine:

| Agent | Role | Model (default) |
|---|---|---|
| **Collector** | recon + run scanners → normalized findings | `claude-haiku-4-5` |
| **Analyst** | correlate + rank + NL query *(core IP)* | `claude-opus-4-7` |
| **Author** | reports + remediation PRs + audit | `claude-sonnet-4-6` |

The engine (`packages/engine-claude` → `engine-hermes`) is injected at the
composition root (`apps/api`). All product IP depends only on the `AgentEngine`
interface in `@k8s-sentinel/core` — never on a concrete engine.

## Workspace

| Package | Purpose | Status |
|---|---|---|
| `packages/core` | engine interface, findings schema, sanitizer, audit | ✅ Phase 0 |
| `packages/engine-claude` | Claude Agent SDK adapter (default) | ✅ Phase 0 |
| `packages/tools-mcp` | Trivy/Kubescape/kube-bench/Falco wrappers | Phase 1 |
| `packages/agent-collector` | recon + scan → `Finding[]` | Phase 1 |
| `packages/agent-analyst` | correlation + ranking + NL query | Phase 2 |
| `packages/agent-author` | reports + remediation + audit | Phase 3 |
| `packages/engine-hermes` | air-gapped local-model adapter | Phase 4 |
| `apps/api` | Fastify + tRPC orchestrator (SSE) | Phase 0→3 |
| `apps/dashboard` | Apple-like Next.js UI (6 screens) | Phase 3 |
| `deploy/helm` | read-only RBAC, sandbox, egress allow-list | ✅ Phase 0 |

See [`docs/PROGRESS.md`](docs/PROGRESS.md) for phase-by-phase status.
