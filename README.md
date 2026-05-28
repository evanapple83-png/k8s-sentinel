# K8s Sentinel

> Autonomous, **self-hosted** AI security agent for Kubernetes. Runs an attack-graph
> engine (CISA-KEV-aware) on top of best-of-breed open-source scanners, correlates
> findings into **ranked attack paths + choke-points**, and ships audit-ready reports
> — **read-only by default**, never auto-applies anything.

See [`docs/BUILD.md`](docs/BUILD.md) for the original spec and
[`CLAUDE.md`](CLAUDE.md) for the working contract.

---

## Live today

- **Hosted dashboard** — https://control-plane-azure.vercel.app
- **Relay** (stateless WS forwarder) — `wss://k8s-sentinel-relay.fly.dev`
- **Agent image** — `ghcr.io/evanapple83-png/k8s-sentinel:0.2.0-argus-v3`

The hosted dashboard runs in two modes:
- **Demo** — sign-in optional; renders against a built-in payment-api dataset so
  you can see every screen with one click.
- **Live** — sign in, mint a cluster connection from the **Connect** screen, and
  scan an actual cluster (Helm or Public-key method, both supported).

---

## Connect a cluster — two methods

### Helm install (in-cluster agent)

Best for clusters you'll keep scanning; works behind firewalls and in air-gap.
The agent runs inside the cluster and dials OUT to the relay — no inbound port.

```bash
# 1. In the dashboard: Connect → Helm install → copy your install token
kubectl -n sentinel create secret generic sentinel-install \
  --from-literal=SENTINEL_INSTALL_TOKEN=sit-…

# 2. Install the chart (pulls the unified ARGUS v3 image from ghcr)
helm install sentinel deploy/helm \
  --namespace sentinel --create-namespace \
  --set mode=hybrid \
  --set relay.url=wss://k8s-sentinel-relay.fly.dev \
  --set relay.installTokenSecret=sentinel-install
```

The dashboard's stepper flips to **connected** as soon as the agent registers,
typically in <15 seconds.

### Public-key (out-of-cluster, no install) — *new*

Best for quick tests and admins who don't want to deploy an agent. The CLI
generates a fresh keypair locally; the cluster signs a short-lived,
read-only client certificate it explicitly approves; the private key never
leaves your machine.

```bash
# 1. In the dashboard: Connect → Public key → copy the command
# 2. On a host with cluster-admin kubeconfig:
python3 -m argus.cli bootstrap csr \
    --enroll ent_<token-from-UI> \
    --control-plane https://control-plane-azure.vercel.app \
    --auto-approve --cleanup     # --auto-approve only for kind/dev clusters
```

The stepper drives through *Command issued → CSR submitted → Awaiting approval
(prints the exact `kubectl certificate approve` command) → Approved → First scan
received ✅*.

Both methods feed the same posture pipeline and the same dashboard screens.

---

## Air-gap (sovereign) mode

For disconnected / classified networks, swap the LLM engine to a local
open-weight model and make **zero external calls** — same product, same agents:

```bash
helm install sentinel deploy/helm \
  --set engine.kind=hermes \
  --set engine.hermes.baseUrl=http://hermes:8080/v1 \
  --set sandbox.enabled=true --set sandbox.runtimeClassName=gvisor
```

The chart drops all public egress automatically when `engine.kind=hermes`.

---

## Architecture

```
                                    ┌────────────────────────────┐
   In-cluster agent ── WSS dial ───►│  Relay (Fly, stateless)   │
   (helm install OR                 │  forwards frames, mTLS    │
   cert from CSR)                   └────────────┬───────────────┘
                                                 │ ingest webhook
                                                 ▼
                                    ┌────────────────────────────┐
                                    │  Hosted control plane     │
                                    │  (Vercel + Supabase)      │
                                    │  • dashboard (6 screens)  │
                                    │  • tenant scoping (RLS-   │
                                    │    enabled, code-enforced) │
                                    │  • normalized posture     │
                                    └────────────────────────────┘
```

**Inside the agent pod** (unified image):

| Process | Role |
|---|---|
| TS tunnel-client (PID 1) | Durable WSS connection to the relay |
| Python ARGUS engine | v3 attack-graph correlation, CISA-KEV-aware, SSVC-tiered |
| Trivy (pinned 0.70.0) | Image / cluster CVE scanner |
| Kubescape (3.0.20) | Posture & CIS misconfig scanner |
| kube-bench (0.7.3) | Control-plane CIS benchmark |

`SENTINEL_SCANNER=argus` is the production default; `=builtin` falls back to
the legacy TS orchestrator for emergency rollback or A/B comparison.

**Three specialized LLM agents** (still present for explain / fixes / NL query):

| Agent | Role | Default model |
|---|---|---|
| **Collector** | recon + scanner orchestration → normalized findings | `claude-haiku-4-5` |
| **Analyst** | correlate + rank + NL query *(legacy core IP, now flanked by ARGUS)* | `claude-opus-4-7` |
| **Author** | reports + remediation PR bundles + audit | `claude-sonnet-4-6` |

The engine boundary in `@k8s-sentinel/core` lets `engine-claude` ↔ `engine-hermes`
swap with **no change** to agent/IP code.

---

## Workspace

| Package / app | Purpose |
|---|---|
| `argus/` | **Python attack-graph engine** (v3) — read-only collector, Trivy/kube-bench/Kubescape adapters, CISA-KEV ingest, SSVC scoring, choke-point analysis, CSR bootstrap CLI |
| `packages/core` | Engine interface, findings schema, sanitizer, hash-chained audit |
| `packages/engine-claude` | Claude Agent SDK adapter (default) |
| `packages/engine-hermes` | Air-gapped local-model adapter (zero external calls) |
| `packages/tools-mcp` | Trivy / Kubescape / kube-bench / Falco TS wrappers (legacy path) |
| `packages/agent-collector` | Recon + scan → `Finding[]` |
| `packages/agent-analyst` | Correlation + ranking + NL query |
| `packages/agent-author` | Reports (PDF / MD / JSON / HTML) + remediation PRs |
| `packages/relay-protocol` | Self-contained zod wire contract (trust boundary) |
| `apps/api` | TS orchestrator + tunnel-client (PID 1 in agent pod) + ARGUS subprocess bridge |
| `apps/relay` | Stateless WS forwarder (Fly.io), mTLS, ingest webhook, command bridge |
| `apps/control-plane` | Next 16 hosted dashboard (Vercel + Supabase), multi-tenant |
| `apps/dashboard` | Legacy in-cluster Apple-like Next.js UI (still present for cluster-local mode) |
| `deploy/helm` | Read-only RBAC (zero secrets verbs), sandbox, egress allow-list, ARGUS knobs |

---

## Development

```bash
pnpm install
pnpm build
pnpm typecheck    # 20 packages
pnpm test         # 19 packages, ~220 vitest cases

# Python side (ARGUS engine + bootstrap CLI)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest argus/tests/    # 95 tests
```

End-to-end runbook for a real cluster: [`docs/GO_LIVE.md`](docs/GO_LIVE.md).
Connect-screen build spec: [`docs/PUBKEY_CONNECT_SPEC.md`](docs/PUBKEY_CONNECT_SPEC.md).
Wire contract between agents + control plane: [`packages/relay-protocol`](packages/relay-protocol)
and [`docs/PUBKEY_CONNECT_CONTRACT.md`](docs/PUBKEY_CONNECT_CONTRACT.md).

---

## Security posture (non-negotiable)

1. **Read-only by default.** RBAC is strictly `get,list,watch` — **zero `secrets`
   verbs anywhere.** ARGUS derives Secret reachability from RBAC + pod volume
   mounts, never from Secret data.
2. **Propose, don't apply.** All cluster/repo writes are emitted as reviewable
   PR bundles requiring human approval.
3. **Untrusted scan input** is sanitized at the `BaseScanner` chokepoint before
   anything reaches an LLM (prompt-injection defense).
4. **Everything is logged** — hash-chained immutable audit (`audit_entry`) for
   every agent decision, tool call, and command.
5. **Egress allow-list.** Default-deny NetworkPolicy; in Hermes (air-gap) mode
   there are **zero** external calls.
6. **Web app never holds cluster creds.** Public-key method: keypair + CSR live
   only on the user's machine; the dashboard sees the resulting posture, not
   the private key.

See [`docs/DATA-BOUNDARY.md`](docs/DATA-BOUNDARY.md) for the exact bytes that
ever leave a cluster.

---

## Status

| Phase | Status |
|---|---|
| 0 — Foundations | ✅ |
| 1 — Collector | ✅ |
| 2 — Analyst (correlation, NL query) | ✅ |
| 3 — Author + UI (6 screens, PDF, approve) | ✅ |
| 4 — Hardening + Hermes air-gap | ✅ |
| 5a — Hosted control plane (Vercel + Supabase + relay) | ✅ live |
| 5b — ARGUS v3 attack-graph engine (CISA-KEV) | ✅ live, default scanner |
| 5c — Public-key cluster connect (CSR-based, no install) | ✅ live (`FEATURE_PUBKEY_CONNECT=1` on prod) |

See [`docs/PROGRESS.md`](docs/PROGRESS.md) for the detailed phase-by-phase log.
