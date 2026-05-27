# CLAUDE.md — K8s Sentinel

> Read `docs/BUILD.md` first. It is the authoritative build spec (architecture, phases, security model). This file is the working contract for how to build in this repo.

## What this is

An autonomous, **self-hosted** AI security agent for Kubernetes. It orchestrates open-source scanners (Trivy · Kubescape · kube-bench · Falco), correlates their findings into **ranked attack paths** (the core IP), and ships audit-ready reports. Runs inside the customer's cluster, **read-only by default**, with an Apple-like web dashboard.

## Non-negotiable rules (security model — see BUILD.md §10)

1. **Read-only by default.** Scanning never needs write. Never widen RBAC beyond read.
2. **Propose, don't apply.** All cluster/repo writes are emitted as reviewable diffs/PRs requiring human approval. **No agent auto-applies anything.**
3. **Untrusted scan input.** Image tags, annotations, CVE text, scanner output → treated as hostile. Sanitize before it enters any agent prompt context (prompt-injection defense). Use `@k8s-sentinel/core` `sanitizeUntrusted()`.
4. **Everything is logged.** Every agent decision, tool call, and command goes to the immutable audit log (`AuditEntry`).
5. **Egress allow-list.** Outbound traffic is restricted. In Hermes (air-gap) mode there are **zero** external calls.

## The engine boundary is sacred (BUILD.md §5)

- Agent/IP code (`agent-*`, `tools-mcp`, correlation, report templates) **must not import** from `engine-claude` or `engine-hermes` directly.
- They depend only on the `AgentEngine` interface exported by `@k8s-sentinel/core`.
- The engine is injected at the composition root (the API/orchestrator). Swapping Claude ↔ Hermes must require **no change** to agent/IP code.

## Repo layout

```
apps/dashboard     Next.js (App Router) — Apple-like UI (6 screens)
apps/api           Fastify + tRPC orchestrator API (SSE to dashboard)
packages/core      engine interface, findings schema (SARIF-based), shared types, sanitizer, audit log
packages/engine-claude   Claude Agent SDK adapter (DEFAULT)
packages/engine-hermes   Hermes adapter (Phase 4, air-gap)
packages/agent-collector recon + scan → normalized Finding[]
packages/agent-analyst   correlate + rank + NL query (CORE IP)
packages/agent-author    report (PDF/MD/JSON) + remediation PRs + audit
packages/tools-mcp        Trivy/Kubescape/kube-bench/Falco wrappers
deploy/helm        chart, read-only RBAC, sandbox policy
docs               BUILD.md (spec) + design notes
```

## Conventions

- **TypeScript everywhere**, ESM (`"type": "module"`), strict mode. Node ≥ 20.
- Package names: `@k8s-sentinel/<dir>`. Internal deps use `workspace:*`.
- Each package builds with `tsc` to `dist/`. The API/CLI run via `tsx` in dev.
- Tests: **Vitest**, colocated as `*.test.ts`. Pure logic (schema, correlation, normalizers) must have tests.
- No secrets in code. Config comes from env (see `.env.example`).
- Keep tool output parsing defensive — scanners change formats; never trust shape.

## Commands

```bash
pnpm install         # bootstrap workspace
pnpm build           # turbo: build all packages
pnpm typecheck       # turbo: tsc --noEmit across workspace
pnpm test            # turbo: vitest
pnpm lint            # turbo: lint
pnpm --filter @k8s-sentinel/api dev        # run orchestrator API
pnpm --filter @k8s-sentinel/dashboard dev  # run dashboard
```

## How to work here

- **One phase at a time** (BUILD.md §11). Each phase has a Definition of Done; produce it, add tests, self-verify, don't touch other phases.
- Use parallel subagents for independent work (e.g. the four scanner wrappers).
- When a scanner binary or live cluster is unavailable, code against the fixtures in `packages/tools-mcp/fixtures/` so the pipeline runs end-to-end offline.
