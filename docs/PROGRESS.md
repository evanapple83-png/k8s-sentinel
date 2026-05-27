# Build progress

Tracks the phased plan in `BUILD.md §11`. Each phase ships and has a DoD.

## ✅ Phase 0 — Foundations

- [x] pnpm + Turborepo monorepo, `tsconfig.base`, prettier, `.gitignore`, `.env.example`
- [x] `CLAUDE.md` working contract + `docs/BUILD.md` spec
- [x] CI workflow (build · typecheck · test · helm lint)
- [x] `packages/core`: `AgentEngine` interface, SARIF-based findings schema,
      `AttackPath`, hash-chained `AuditSink`, untrusted-input `sanitizeUntrusted`,
      offline `MockEngine`
- [x] `packages/engine-claude`: Claude Agent SDK adapter (`query()` wrapper),
      read-only tool allow-list, structured-output extraction
- [x] `apps/api`: config loader + engine factory (composition root)
- [x] `deploy/helm`: read-only RBAC (get/list/watch only), egress allow-list
      NetworkPolicy, hardened pod security contexts, sandbox RuntimeClass hook
- [x] **DoD:** trivial agent runs through the engine adapter and writes a
      verified audit entry (`pnpm --filter @k8s-sentinel/api phase0`)

> Note: in this environment there is no `ANTHROPIC_API_KEY`, so the DoD demo
> exercises the identical code path through the offline **Mock** engine. With a
> key set it runs through the real **Claude** adapter unchanged.

## ✅ Phase 1 — Collector (Features 1, 7-foundation)

- [x] `packages/tools-mcp`: Trivy · Kubescape · kube-bench · Falco wrappers
      (CLI exec + offline fixtures, defensive parsers, severity normalization)
- [x] read-only cluster connect + inventory (`collectInventory`, fixture fallback)
- [x] parallel scan → normalize → de-duplicated `Finding[]`
- [x] persist findings + inventory (SQLite, `node:sqlite`)
- [x] **DoD:** `sentinel scan` produces a normalized, persisted findings set from
      all four tools (offline fixtures when no live cluster/scanners present)

## ✅ Phase 2 — Analyst (Features 2, 4) — *core IP*

- [x] reachability: enrich findings with `reachable` + reachability-weighted
      `exploitScore` (NOT raw CVSS); workload attribution across Trivy/Kubescape/
      Falco/kube-bench resource shapes
- [x] correlation: fuse findings into ranked `AttackPath[]` with narratives
      (exposed → running → vulnerable → over-privileged → secret-access)
- [x] compliance mapping: CIS · NSA-CISA · SOC 2 · MITRE ATT&CK
- [x] plain-English query engine (`answerQuery`) over the posture graph +
      `sentinel ask` / `sentinel paths` CLI; injection-safe answers
- [x] analyst wired into the orchestrator; enriched findings + paths + posture
      risk score persisted; `analyze.correlated` audit entry
- [x] **DoD:** findings reranked by reachability; "show everything
      internet-exposed running as root" returns exactly the reachable, root,
      internet-exposed `payment-api` (frontend excluded). 14 analyst tests.

## 🟡 Phase 3 — Author + UI (Features 3, 5, 6)

**Phase 3a — Author agent + API (backend) ✅**

- [x] `packages/agent-author`: propose-only Agent 3. Pure/deterministic, offline.
  - [x] playbook library (`playbooks.ts`): pin-image · drop-privileged ·
        restrict-rbac · add-network-policy · read-only-root-fs · node-hardening ·
        runtime-detection, matched against the real normalized findings
  - [x] reviewable remediations (`remediation.ts`): grouped + reachability-ranked
        `RemediationProposal[]` + `buildPrBundle` (representative manifest diff +
        ready-to-open PR body). Stable ids, propose-only — never applies
  - [x] dependency-free unified-diff generator (`diff.ts`, LCS)
  - [x] reports (`report.ts` + `pdf.ts`): one injection-safe model → Markdown /
        JSON / Apple-like HTML / **dependency-free PDF** (no headless browser)
  - [x] 14 author tests (matching · dedup/ranking · diff · render · PDF · injection)
- [x] Author wired into the orchestrator → `fixes.proposed` audit entry
- [x] `apps/api/src/server.ts`: node:http + **SSE** API (health · live scan stream ·
      runs · findings · paths · fixes · report export · audit[+verify] · approve · ask)
- [x] `apps/api/src/reporting.ts`: shared report/approve helpers (CLI + server)
- [x] CLI: `sentinel report|fixes|approve|audit|serve`
- [x] **DoD (backend):** e2e offline — `scan` → ranked findings + attack paths →
      `report --format pdf` (valid 4-page PDF) / json / md → `fixes` → `approve`
      writes a reviewable PR bundle → `audit --verify` chain intact (incl.
      `author:fixes.proposed` + `user:fix.approved`). Verified over the CLI **and**
      the HTTP/SSE server. 63 tests green.

**Phase 3b — Apple-like dashboard (the 6 screens over SSE) — next.**
Backend contract is in place (`apps/api/src/server.ts`); `apps/dashboard` still empty.

## Phase 4 — Hardening + Hermes

Not started. Prompt-injection hardening on scan input, sandbox separation, egress
allow-list, Helm one-command install, and the `engine-hermes` air-gap adapter.
