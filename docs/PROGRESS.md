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

## ✅ Phase 3 — Author + UI (Features 3, 5, 6)

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

**Phase 3b — Apple-like dashboard (the 6 screens over SSE) ✅**

- [x] `apps/dashboard`: Next 16 (App Router, React 19), standalone browser app —
      talks to the orchestrator API over HTTP/SSE, imports no Node-only backend code
- [x] design system (`globals.css`) from BUILD.md §8 tokens; light/dark; sidebar
      shell + run picker + live `RunProvider` context (`lib/run-context.tsx`)
- [x] the 6 screens:
  - **Overview** — risk ring, posture summary, severity/scanner breakdown,
    "since last scan" delta, **live scan over EventSource** (`scan-button.tsx`)
  - **Findings** — exploitability-ranked list, severity/source/reachable/search filters
  - **Attack Paths** — correlated chain rendered as an entry→step node graph
  - **Ask** — Spotlight-style NL query bar (POST /api/ask)
  - **Report** — inline HTML report + one-click PDF/MD/JSON export
  - **Fixes** — remediation cards with colorized diff/steps; **Approve → PR** (POST approve)
- [x] **DoD (full):** `next build` green (7 static routes); served dashboard +
      `sentinel serve` API verified together — Overview→Findings→Paths→Ask→Report→Fixes
      drive the same scan/correlate/report/approve flow end-to-end in the browser UI.

> **Phase 3 complete — all of Features 1–6 present (Claude default / offline fixtures).**

## ✅ Phase 4 — Hardening + Sovereignty (Features 7, 8) + Hermes

- [x] **`packages/engine-hermes`: `HermesEngine implements AgentEngine`** — the
      air-gap brain. Dependency-free OpenAI-compatible Chat Completions client
      (works with vLLM/llama.cpp/Ollama/TGI), bounded tool-call turn-loop,
      structured-JSON extraction, full `AgentEvent` streaming. Injectable `fetch`
      so it's fully testable offline. Talks to exactly ONE endpoint (the local
      `baseUrl`); `assertLocalUrl` refuses any public host by default.
- [x] **Injection hardening enforced at the scan-input chokepoint** —
      `hardenFindings` (core) defangs the NORMALIZED `title`/`description`/
      `resource.*` fields (not just `raw`), applied in `BaseScanner` so every
      path that yields findings (live CLI *or* fixture) is sanitized once. Stable
      `id`/`ruleId`/severity/scores preserved.
- [x] **Engine selectable by config** — `createEngine` returns the working
      Hermes engine on `SENTINEL_ENGINE=hermes`; agents/IP unchanged (the engine
      boundary held). Air-gap endpoint validated; public endpoints rejected.
- [x] **Helm one-command install + air-gap polish** — `engine.kind=hermes` alone
      drops ALL public egress (NetworkPolicy renders DNS + private CIDRs only,
      zero `0.0.0.0/0`), wires `HERMES_*` env, omits the Anthropic secret, and
      annotates `mode: air-gap`. Added `Service` + post-install `NOTES.txt`.
      Claude mode keeps 443 egress for the managed API. `helm lint` clean; both
      modes `helm template` render valid manifests.
- [x] **DoD:** the identical product runs in **two modes selectable by config** —
      `sentinel scan` produces the same 14 findings + 2 ranked attack paths under
      the default engine and under `SENTINEL_ENGINE=hermes`; the run is recorded
      `engine=hermes` in the immutable audit log with **zero external calls**, no
      change to any agent/IP code. 76 tests green (engine-hermes 10, core +6
      hardening, tools-mcp +1 chokepoint, api air-gap selection).

> **MVP complete — all eight features present. Claude (default) and Hermes
> (air-gapped) are drop-in interchangeable behind the engine boundary.**

## ✅ Phase 5 — Hybrid hosted control-plane

**UI track (1A–1F) ✅** — `apps/control-plane` (Next 16 + Supabase + NextAuth):
scaffold, multi-tenant schema + RLS, the 6 product screens, SSO + TOTP MFA +
roles, install-token onboarding, live tenant-scoped data, permissions UX +
`docs/DATA-BOUNDARY.md`. Dual-mode: demo (no env) ↔ live (Supabase).

**fase 2 — relay + live data-plane ✅**

- [x] `packages/relay-protocol`: self-contained, zod-validated wire contract
      (the trust boundary). Discriminated message union, size-capped
      `PostureSnapshot`, codec (`encode`/`decode`), injectable `Transport` +
      in-memory pair. 10 tests.
- [x] `apps/relay`: **stateless** WebSocket forwarder (Fly.io). Registry keyed by
      clusterId, pluggable mTLS verifier (CN = clusterId), control↔agent routing
      with anti-spoofing re-stamping, idle sweep, an `onSnapshot` ingest webhook,
      and an HTTP `/command` RPC bridge (so a serverless control plane drives a
      cluster without holding a socket). Persists no payloads. 18 tests + real-
      socket + HTTP data-plane smokes.
- [x] `apps/api` tunnel-client (`sentinel agent`): dials OUT (no inbound port),
      registers (install token / mTLS), serves down-commands via the SAME
      orchestrator/reporting paths as the SSE server, streams posture up.
      Reconnect/backoff. 11 tests.
- [x] Control-plane ingest: `ingestSnapshot` + migration `0004` (remediations)
      → real run/findings/paths/fixes land in tenant tables (replacing the
      placeholder run); re-validated against a local wire schema; "Scan now"
      triggers a command through the relay bridge.
- [x] Deploy: relay `Dockerfile` + `fly.toml`, `deploy/relay/relay-ca.sh` (mTLS
      CA + per-cluster cert issuance), Helm `mode=hybrid` (agent dial-out + cert
      mount + relay egress), env docs, and the runbook in `DEPLOY.md §3`.
- [x] **DoD:** end-to-end over real sockets/HTTP — agent dials the relay,
      registers, a control command drives a scan, and the posture flows up the
      tunnel and through the ingest webhook into the hosted store, all with the
      clusterId relay-stamped (no tenant spoofing). 119 tests green.

> Phase 5a went live on 28 May 2026: relay deployed to Fly
> (`k8s-sentinel-relay.fly.dev`), control plane on Vercel
> (`control-plane-azure.vercel.app`), Supabase project `fmdrkydbihmmemddqdvp`
> in production with migrations 0001–0004 applied.

## ✅ Phase 5b — ARGUS v3 attack-graph engine (default scanner)

Replaces the TS-only legacy orchestrator path with a deterministic Python
attack-graph engine bundled into the same agent image. CISA-KEV-aware,
SSVC-tiered, choke-point-ranked.

- [x] **Python `argus/` package** — read-only k8s collector (`inventory.py`),
      scanner adapters (`scanners.py` — Trivy / kube-bench / Kubescape, missing
      binaries degrade gracefully), the deterministic v3 engine
      (`engine_v3/engine.py` — scoring, attack-path, accepted-risk governance,
      frozen as the source of truth), CISA-KEV live fetch + cache + override,
      EPSS / SSVC scoring, choke-point analysis, `argus scan` CLI.
- [x] **TS bridge** (`apps/api/src/tunnel/argus.ts`, 600 LOC) — spawns the
      Python pipeline as a short-lived subprocess on each `scan` command,
      validates the result against `PostureSnapshotSchema` in-cluster, maps
      onto typed v3 wire fields. `SENTINEL_SCANNER=argus` (default) /
      `=builtin` (legacy rollback). 22 vitest tests.
- [x] **Wire contract widened** — `packages/relay-protocol` adds optional
      `cve / kev / ransomware / epss / ssvc / confidence / exposure / reaches`
      on `WireFinding`, plus typed `WireChokePoint[]` and `WireThreatIntel`
      on `PostureSnapshot`. Backward-compatible (all optional).
- [x] **Supabase migration 0005** — v3 columns on `finding` + `run`, new
      `choke_point` table, partial indexes for `kev = true` and `ssvc = 'Act'`.
      Applied to `fmdrkydbihmmemddqdvp` via the Supabase MCP.
- [x] **Dashboard renders v3** — `IntelBanner` shows the pinned KEV catalog
      version on every screen; Overview gets 4 stat-tiles (Critical / KEV /
      SSVC Act / Reachable) + `ChokePointsPanel` ("Apply first" ranked
      single-control fixes that collapse N attack paths each); FindingsTable
      grows an Intel column with KEV / Ransomware / SSVC / EPSS badges + a
      KEV-only filter chip + SSVC tier chips.
- [x] **Unified image** — `apps/api/Dockerfile` now packages TS tunnel-client
      + Python ARGUS + pinned Trivy 0.70.0 / kube-bench 0.7.3 / Kubescape
      3.0.20 in one nonroot image. `libc6-compat` shim for kube-bench's
      glibc binary on alpine musl. Published as
      `ghcr.io/evanapple83-png/k8s-sentinel:0.2.0-argus-v3` (+ `argus-v3`,
      `latest`).
- [x] **Helm chart bump → 0.2.0-argus-v3** — `argus.*` knobs (scanner,
      imagesOnly, noNetwork, acceptedRisks ConfigMap mount for GitOps
      waivers). RBAC tightened: the chart's ClusterRole now has **zero
      `secrets` verbs** (the legacy `secrets: ["list"]` rule is removed —
      ARGUS doesn't need it).
- [x] **DoD:** end-to-end live in production. Hosted dashboard renders v3
      shapes; Supabase persists v3 columns + choke_point rows; GHCR image
      builds clean with all five scanner binaries on PATH; helm chart pins
      the matching tag. **95 Python tests + 37 apps/api TS tests + 222 total
      workspace tests green.** Docs: `docs/GO_LIVE.md`,
      `docs/argus-scanner-agent.md`, `docs/argus-go-live-task.md`.

## ✅ Phase 5c — Public-key cluster connect (CSR-based, no install)

A second cluster-connect method next to Helm: the user runs one CLI command
that generates a fresh keypair locally, submits a CSR, gets it approved by
a cluster-admin, and the agent authenticates as a short-lived read-only
client-cert user. Nothing is installed in-cluster. Built by two parallel
agents against a frozen wire contract, then integrated.

- [x] **Backend** (`apps/control-plane`) — Supabase migration 0006
      (`cluster_enrollment` + `connection_event` + `scans`), `lib/pubkey-connect.ts`
      (token mint with sha256-only storage, constant-time hash compare,
      event reducer → cluster status projection, scan ingest that fans out
      via the existing `ingestSnapshot` so legacy screens keep rendering),
      5 new API routes (`POST /api/clusters`, `GET /api/clusters/[id]`,
      `POST /api/clusters/[id]/events`, `POST /api/scans`, `GET /api/clusters/self`).
      All gated by `FEATURE_PUBKEY_CONNECT` (404 when off).
- [x] **CLI** (`argus/`) — `argus bootstrap csr` subcommand (820 LOC) with
      EC P-256 keypair (private key 0600 temp file, atexit cleanup),
      `CertificateSigningRequest` submit (`signerName=kubernetes.io/kube-apiserver-client`,
      configurable `--ttl`), approval gate (default prints the exact
      `kubectl certificate approve` command; `--auto-approve` for kind/dev),
      read-only `ClusterRoleBinding` to `CN=argus-agent-<…>, O=argus-readonly`
      (matching the Helm-path RBAC exactly — **zero secrets verbs**), scoped
      agent kubeconfig, scan + push, optional `--cleanup`. Also a
      `--bootstrap csr` shortcut on the existing `scan` subcommand.
      Stdlib-only `events_client.py` for the Bearer-token API calls.
      27 pytest cases.
- [x] **UI** (`apps/control-plane`) — segmented `[ Helm install ] [ Public key ]`
      control on `/connect`; Public-key tab has the copy-paste CLI command +
      status stepper (`Command issued → CSR submitted → Awaiting admin
      approval → Approved → First scan received ✅`) driven by a 3s poller
      on `GET /api/clusters/:id`; Regenerate button mirrors the Helm tab.
      21 vitest cases.
- [x] **Security model** — enrollment token format `ent_<base64url(32)>`,
      15 min TTL, single-use, sha256-only at rest; the web app never sees
      the private key; client certs aren't revocable in K8s so short TTL
      (default 3600 s) is the documented mitigation. Wire contract:
      `docs/PUBKEY_CONNECT_CONTRACT.md`.
- [x] **One contract deviation** — the spec writes `/api/clusters/_self` but
      Next.js App Router treats `_`-prefixed folders as private (unrouted).
      Renamed to `/api/clusters/self` on both sides; semantics identical.
- [x] **DoD:** PR #6 merged to main, deployed to `control-plane-azure.vercel.app`,
      `FEATURE_PUBKEY_CONNECT=1` set in Vercel production env — the new
      method is live, the segmented toggle appears, and the public-key flow
      can drive a real cluster end-to-end. Feature-flag default off keeps
      the legacy single-method UI byte-identical until explicitly enabled.

> All eight original product features (Phase 0–4) plus the hosted hybrid
> mode (5a) plus the v3 attack-graph engine (5b) plus the second connect
> method (5c) are live in production on 28 May 2026.
