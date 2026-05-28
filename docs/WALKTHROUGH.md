# K8s Sentinel — End-to-End Walkthrough

A transparent, step-by-step guide to **how the live system actually works** and
**how to use it** — from the mental model, through signing in, to onboarding a
real cluster and reading its security posture.

Nothing here is a black box: every step says *what you do*, *what happens under
the hood*, and *how to verify it*.

---

## 0. The 60-second mental model

K8s Sentinel has **two halves** connected by a **relay**:

```
   YOUR CLUSTER (private)                 HOSTED BY YOU (the cloud)
 ┌────────────────────────┐            ┌──────────────────────────────┐
 │  sentinel agent        │            │  relay (Fly.io)              │
 │  • read-only scans      │            │  • stateless forwarder        │
 │  • correlates findings  │  outbound  │  • holds NO data              │
 │  • proposes fixes       │ ── wss ──▶ │  • routes msgs both ways      │
 │  • dials OUT (no inbound)│           │                               │
 └────────────────────────┘            │        │ HTTP webhook          │
                                        │        ▼                       │
                                        │  control-plane (Vercel)       │
                                        │  • the web dashboard          │
                                        │  • writes posture to Supabase │
                                        └──────────────────────────────┘
                                                  │
                                                  ▼
                                          Supabase (Postgres)
                                          tenant-isolated rows
```

**The golden rules** (enforced in code, not just docs — see `docs/DATA-BOUNDARY.md`):
1. The agent is **read-only**. It never needs write access to your cluster.
2. It **proposes** fixes (diffs / PRs) — it never applies anything itself.
3. It dials **outbound** to the relay. There is **no inbound port** to your cluster.
4. Only **normalized posture** leaves the cluster — never secrets, raw manifests,
   credentials, or logs.
5. The relay is a **dumb pipe**: it forwards messages and stores nothing.

---

## 1. Your live deployment

| Component | URL / id | What it is |
|---|---|---|
| **GitHub** | `github.com/evanapple83-png/k8s-sentinel` (private) | the source of truth |
| **Relay** | `https://k8s-sentinel-relay.fly.dev` | the always-on message forwarder (Fly) |
| **Control-plane** | `https://control-plane-azure.vercel.app` | the dashboard + ingest API (Vercel) |
| **Supabase** | project `fmdrkydbihmmemddqdvp` (Frankfurt) | the tenant-isolated database |

**How they authenticate to each other** (three independent secrets):

- **Agent → relay:** an install token (first boot) or an mTLS client cert (optional hardening).
- **Control-plane → relay** (the "Scan now" command bridge): `RELAY_CONTROL_SECRET`.
- **Relay → control-plane** (the posture ingest webhook): `RELAY_INGEST_SECRET`.
- **You → dashboard:** GitHub sign-in (NextAuth) + TOTP MFA for approver/admin.

> Under the hood: the relay never sees user logins, and the dashboard never holds
> a connection into your cluster. Each hop has its own, narrow credential.

---

## 2. How one scan travels (the data path)

This is the whole product in six hops. Follow a single scan:

1. **Trigger.** You click **Scan now** in the dashboard (or the agent runs on a
   schedule). → The control-plane calls the relay's `POST /command` (auth:
   `RELAY_CONTROL_SECRET`).
2. **Relay → agent.** The relay looks up the live WebSocket for *your* cluster and
   forwards a `scan` command down it. (It can only command the cluster you're
   subscribed to — it re-stamps the cluster id so one tenant can't touch another.)
3. **Agent scans.** In-cluster, the agent runs the read-only collectors
   (Trivy/Kubescape/kube-bench/Falco — or offline fixtures), the **Analyst**
   correlates findings into ranked **attack paths**, and the **Author** proposes
   remediations. All scanner text is **sanitized in-cluster** before anything is sent.
4. **Agent → relay → control-plane.** The agent streams a `snapshot` (run +
   findings + paths + remediations + audit) up the tunnel. The relay forwards it to
   the control-plane's `POST /api/agent/ingest` webhook (auth: `RELAY_INGEST_SECRET`).
5. **Validate + persist.** The ingest route **re-validates** the payload against a
   strict schema (it's a trust boundary), resolves which tenant the cluster belongs
   to, and writes the rows into Supabase — scoped to your account.
6. **Render.** You open the dashboard; it reads those rows (tenant-scoped) and shows
   the risk ring, findings, attack paths, report, and fixes.

> Verify it yourself: the ingest endpoint returns `401` without the secret and
> `201` with it — i.e. it's locked down and only the relay can feed it.

---

## 3. Sign in & first run (the dashboard)

1. Open **https://control-plane-azure.vercel.app**.
   - ⚠️ Use exactly this host — it's the one registered in the GitHub OAuth app's
     callback. Other Vercel aliases will fail the OAuth redirect.
2. Click **Continue with GitHub** → authorize.
   - *Under the hood:* on first sign-in the app **provisions** you — it creates
     your `app_user` row, a personal `account`, and a `membership` with role
     **admin**. You land inside your own tenant.
3. **Enroll MFA.** As an admin you'll be sent to `/mfa`: scan the TOTP QR with any
   authenticator app (1Password, Authy, Google Authenticator) and enter the code.
   - *Why:* approver/admin actions (minting install tokens, approving fixes) are
     privileged, so they're gated behind a second factor.
4. You're in. The six screens: **Overview** (risk), **Findings**, **Attack Paths**,
   **Ask** (plain-English queries), **Report** (export PDF/MD/JSON), **Fixes**
   (reviewable diffs → PRs). Until a cluster connects, they're empty.

---

## 4. Onboard your first cluster

### Prerequisite (important, honest)

The Helm chart pulls the agent **container image** from a registry. That image
**isn't published yet** — the chart points at a placeholder
(`ghcr.io/your-org/k8s-sentinel`). Before a real cluster can run the agent you must
build and push it once:

```bash
# from the repo root — build the agent image (apps/api running `sentinel agent`)
# and push to a registry you control, then point the chart at it:
#   helm install ... --set image.repository=ghcr.io/<you>/k8s-sentinel --set image.tag=0.1.0
```

> There's a relay Dockerfile (`apps/relay/Dockerfile`) but **not yet** an agent
> image build. That's the single remaining gap for live cluster onboarding — see §7.

### Step 1 — Mint an install token

In the dashboard go to **/connect** → **Generate install command**.

- *What it is:* a **single-use, 15-minute** secret embedded in a copy-paste Helm
  command. Only a SHA-256 **hash** is stored server-side; the raw token is shown once.
- *Why single-use + short-lived:* it's the bootstrap credential that lets a brand-new
  agent prove "I'm allowed to register a cluster for this account" — exactly once.

### Step 2 — Install the agent (read-only)

Run the generated command in a cluster where you're admin. It looks like:

```bash
helm install sentinel oci://ghcr.io/<you>/k8s-sentinel \
  --namespace sentinel --create-namespace \
  --set mode=hybrid \
  --set relay.url=wss://k8s-sentinel-relay.fly.dev \
  --set installToken=sk-install-…
```

*What this actually deploys (all secure-by-default):*
- A **read-only ClusterRole** (`get/list/watch` only — it can list secret *names*,
  never their *values*).
- A **default-deny egress** NetworkPolicy that only allows DNS + outbound 443 to the
  relay. No inbound service, no Ingress.
- A hardened pod (non-root, read-only root FS, all caps dropped).
- The container runs `sentinel agent`, which **dials out** to the relay.

### Step 3 — First boot (what happens automatically)

1. The agent opens a WebSocket to the relay and sends `register` with the install token.
2. The relay calls the control-plane's `/api/agent/register`, which **consumes** the
   token (marks it used), creates a `cluster` row in your account, and returns its id.
3. The relay binds that WebSocket to your cluster id. **/connect flips to "connected".**

### Step 4 — Run a scan

Click **Scan now** on /connect (or the Overview). The command rides the tunnel,
the agent scans, and the posture flows back (the path in §2). Within seconds the
dashboard populates with real data.

### Step 5 (optional) — Harden with mTLS

By default the tunnel is TLS (Fly-terminated) + token auth. To add **mutual TLS**
(per-cluster client certs), use the CA helper and turn it on at the relay:

```bash
deploy/relay/relay-ca.sh init                 # one-time; keep ca.key offline
deploy/relay/relay-ca.sh issue <clusterId>    # prints kubectl + helm to mount it
# then set RELAY_CLIENT_CA on the relay (fly secrets set) so it verifies client certs
```

*What it adds:* the relay then authenticates each agent by a certificate whose
Common Name **is** the cluster id — a spoofed agent can't impersonate another tenant.

---

## 5. The dashboard, screen by screen

- **Overview** — a 0–100 risk ring, posture summary, severity/scanner breakdown, and
  a "since last scan" delta. The risk score is **reachability-weighted**, not raw CVSS.
- **Findings** — every normalized finding, ranked by **exploitability** (is it actually
  reachable?), with severity/source/reachable/search filters.
- **Attack Paths** — findings **fused** into ranked narratives
  (exposed → running → vulnerable → over-privileged → secret-access). This is the core IP.
- **Ask** — type "show everything internet-exposed running as root"; it answers over
  the posture graph (injection-safe).
- **Report** — an audit-ready report, exportable as PDF / Markdown / JSON.
- **Fixes** — remediation **proposals** as reviewable diffs; **Approve → PR** writes a
  PR bundle. Nothing is ever applied to your cluster automatically.

---

## 6. Operating it

**Secret map (who knows what):**

| Secret | Lives on | Purpose |
|---|---|---|
| `RELAY_CONTROL_SECRET` | relay **and** control-plane | dashboard → relay commands |
| `RELAY_INGEST_SECRET` | relay **and** control-plane | relay → control-plane ingest |
| `SUPABASE_SECRET_KEY` | control-plane (Vercel) | server-side DB access (bypasses RLS) |
| `AUTH_SECRET` + `AUTH_GITHUB_*` | control-plane (Vercel) | user sign-in |
| install token | minted per onboarding | first-boot agent registration |
| mTLS CA key | your machine, **offline** | signs per-cluster agent certs (optional) |

**Common checks:**
- Relay health: `curl https://k8s-sentinel-relay.fly.dev/healthz` → `{"ok":true,…}`.
- Is the control-plane in live mode? `curl -X POST …/api/agent/ingest` → `401`
  (configured) vs `503` (demo / not configured).
- Disconnect a cluster: deleting it in the dashboard cascades its runs/findings/paths.

**Rotation:** regenerate a secret with `openssl rand -hex 32`, set it on **both**
sides (`fly secrets set …` + Vercel env), redeploy both.

---

## 7. What's live vs. what to improve next

**Live & verified:** GitHub repo · relay on Fly · control-plane on Vercel (live mode +
GitHub sign-in) · Supabase · the full ingest loop (proven end-to-end:
agent→relay→ingest→Supabase).

**To make real cluster onboarding work / to improve:**
1. **Publish the agent image** (the one prerequisite). Build `apps/api` as a container
   that runs `sentinel agent`, push to ghcr.io, point the chart at it. *(Not yet done.)*
2. **CI** to build + push both images (relay + agent) on tag.
3. **Auto-issue mTLS certs** on registration (today the CA is a manual helper; the
   data-boundary spec envisions the relay handing the agent its cert during the token
   exchange).
4. **Scale the relay** to 1 machine while testing (`fly scale count 1`) to trim cost,
   back to ≥2 for HA in production.
5. **Custom domain** for the control-plane (so the URL isn't `*-azure.vercel.app`).

---

*Architecture spec: `docs/BUILD.md`. Data boundary: `docs/DATA-BOUNDARY.md`.
Deploy/runbook: `apps/control-plane/DEPLOY.md §3`. Build status: `docs/PROGRESS.md`.*
