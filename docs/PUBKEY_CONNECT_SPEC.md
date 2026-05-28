# Connect a Cluster — add a "Public key" method next to Helm (build spec)

> Feed this to Claude Code. It extends the existing **Connect your cluster** screen so the
> user can choose between **Helm install** (current) and a new **Public key** method —
> a short-lived X.509 client certificate the cluster *explicitly approves* ("the cluster
> admits us as a read-only user"). Both methods feed the same status tracker and posture page.
>
> **Feature-flag the whole thing; read-only only; do NOT merge to main or deploy.**

## 0. Current state (from the live UI)

- The dashboard `Overview` shows an empty state with a **Connect a cluster** button.
- The **Connect your cluster** screen currently offers **one** method: a copy-paste `helm install …`
  command with an `installToken` and `relay.url`; it shows "Waiting for the agent to register…",
  a **Regenerate** button, and "this page flips to 'connected' automatically."
- Goal: keep that Helm flow exactly as-is, and add a **second method** on the same screen.

## 1. The two methods (and when each is used)

- **Helm install (in-cluster agent, dials out via relay)** — *existing, unchanged.* The agent runs
  inside the cluster and dials out to the relay (no Ingress, no port-forward). Best when you can
  install an agent; works behind firewalls; the path for air-gapped/sovereign clusters.
- **Public key (out-of-cluster, read-only user via CSR)** — *new.* Nothing is installed in-cluster.
  The user runs one CLI command that generates a fresh keypair + CSR; the cluster admin approves it
  and read-only RBAC is bound to that identity; the agent then authenticates as a **short-lived
  client-cert user**. Best for quick tests and admins who don't want to deploy an agent. Requires the
  cluster API server to be reachable from where the command runs, plus one admin approval step.

## 2. Architecture constraints (both methods)

- The **web app never generates keypairs or calls any cluster API.** All crypto and cluster calls
  happen in the CLI the user runs; the private key never leaves that machine and never touches our
  servers. The dashboard is the wizard + live status + results surface only.
- A **single-use, short-TTL enrollment token** ties a CLI run to the dashboard cluster record.
- Both methods feed the **same pipe**: enrollment events → status stepper → scan ingest → posture page.
- **Read-only everywhere:** never read or store Secret `.data`; no write/patch/delete/exec verbs anywhere.

## 3. UI — extend the "Connect your cluster" screen

Add a **method toggle** (segmented control) at the top of the screen: **[ Helm install ] [ Public key ]**.

- **Helm install tab** — the current content, unchanged (command + "Waiting for the agent to register…"
  + Regenerate).
- **Public key tab** — new:
  - Intro: "No agent installed. Your cluster signs a short-lived, read-only certificate it explicitly
    approves. The private key never leaves your machine."
  - Steps: 1) Run this where you have cluster admin — it generates a fresh keypair + CSR locally.
    2) Approve the certificate when prompted. 3) This page flips to "connected" automatically.
  - Copy-paste command (built from the enrollment token):
    `argus bootstrap csr --enroll <token> --control-plane <url>`
  - A **status stepper** driven by the connection events (poll `GET /api/clusters/:id`):
    *Command issued → CSR submitted → Awaiting admin approval* (show the exact
    `kubectl certificate approve <name>` string when it arrives) *→ Approved → First scan received ✅*.
  - A **Regenerate** button (new token), matching the Helm tab.
- On "First scan received," the cluster appears in the **CLUSTER** selector and the Overview renders
  the posture (see §6).

## 4. CLI — `argus bootstrap csr`

`argus bootstrap csr --enroll <token> --control-plane <url>` (and an `argus scan --bootstrap csr` shortcut):

1. Generate a fresh keypair locally each run (EC P-256 or RSA-2048) + a CSR with
   `CN=argus-agent-<short-random>`, `O=argus-readonly`. Private key in a `0600` temp file, cleaned up
   after; only the CSR leaves the machine.
2. Submit a `CertificateSigningRequest` (`certificates.k8s.io/v1`,
   `signerName: kubernetes.io/kube-apiserver-client`, `usages:["client auth"]`, short
   `expirationSeconds` — default `3600`, configurable `--ttl`).
3. Approval gate, two modes: default prints the exact `kubectl certificate approve <name>` command and
   polls until `Approved,Issued`; `--auto-approve` approves programmatically via the admin kubeconfig
   (kind/self-owned clusters).
4. Apply read-only RBAC with the admin kubeconfig: reuse the **same** read-only `ClusterRole` the Helm
   path uses (`get,list,watch` on the read-only resource set; **no `secrets` data; no write/exec**),
   bound via a `ClusterRoleBinding` to the cert identity (`CN`/`O`), named after the run id.
5. Retrieve the signed cert from `status.certificate`; assemble a scoped agent kubeconfig
   (cert+key+cluster CA+server) at `--out` (default `./argus-agent.kubeconfig`).
6. Run the read-only scan with that kubeconfig; push the report to `/api/scans` tagged with the token.
7. `--cleanup`: delete the CSR object + the ClusterRoleBinding on exit; output must note the cert is
   not revocable and expires at its TTL.
8. As it runs, POST the matching status events (§5) so the UI stepper advances live.
9. `--help` documents: certs aren't revocable in Kubernetes → short TTL is the mitigation; approve +
   RBAC require cluster-admin (intentional — the cluster explicitly admits the agent).

## 5. Control-plane / apps/api (shared by both methods)

- `POST /api/clusters` → create a pending connection; return `{ id, enrollmentToken (single-use, short
  TTL) }`. The UI builds the Helm command and the `argus bootstrap csr` command from the token + the
  control-plane/relay URLs.
- `POST /api/clusters/:id/events` (auth = enrollment token) → record progress events. Support both
  method vocabularies: Helm → `agent_registered`; Public key → `csr_submitted`, `awaiting_approval`
  (carry the approve-command string), `approved`; both → `scan_pushed`.
- `GET /api/clusters/:id` → status + event timeline (drives the stepper).
- `POST /api/scans` (auth = enrollment token / cluster id) → validate against the contract in §6,
  store (new `scans` record: id, clusterId, createdAt, report), attribute to the connection.
- Add `clusters` and `scans` to the existing DB.

## 6. Posture rendering (the page the user lands on)

The Overview/posture view fetches the latest scan and renders the **v3 engine** report:
`{ cluster, intel:{source,version,kev_count}, riskScore, reachableJewels[], paths:{target:[[from,to,label,control,inferred],...]}, chokePoints:[{control,breaks,targets[]}], findings:[{id,cve,title,target,kev,ransomware,epss,cvss,exposure,confidence,decision,score,reaches[]}] }`

Render: (a) **risk score** prominently with the KEV catalog version; (b) a **"Do this first"** card
listing each `chokePoint` as "‹fix› — breaks N of M paths"; (c) **Attack paths** as left-to-right step
chains, marking `inferred` edges; (d) **findings table** with SSVC badges (Act/Attend/Track/Track\*),
KEV + ransomware flags, EPSS, exposure, confidence, score. Use the existing design system. (If the
Findings / Attack Paths / Fixes nav pages exist, wire them to the same data.)

## 7. Security & constraints

- Enrollment token single-use + short TTL. Web app never receives the private key or cluster creds.
- Client certs aren't revocable in Kubernetes → short cert TTL is the mitigation (documented in the UI
  and `--help`). Approve + RBAC require cluster-admin — intentional; this is the explicit handshake.
- Read-only scanning unchanged; never read Secret `.data`. Public-key method is out-of-cluster (API
  reachable required); the Helm method remains the air-gapped/sovereign path. Feature-flagged; nothing
  deploys.

## 8. Build order (stop for review after each)

1. **control-plane** — `clusters` + `events` + `scans` (shared by both methods).
2. **CLI** — `argus bootstrap csr` with `--enroll/--control-plane`, events, and report push.
3. **UI** — the method toggle on *Connect your cluster* + the **Public key** tab + status stepper.
4. **Posture rendering** — §6 (if not already wired).
5. **kind smoke** — run the Public-key flow end to end with `--auto-approve`; show the stepper reaching
   "First scan received" and the posture page rendering with live data.

## 9. Definition of done

- On the **Connect your cluster** screen, a **Public key** tab sits beside the existing **Helm install**
  tab; switching tabs swaps the command + steps; Regenerate works on both.
- Running `argus bootstrap csr --enroll … --auto-approve` against a `kind` cluster drives the stepper to
  "First scan received," the cluster appears in the CLUSTER selector, and the Overview shows live posture.
- RBAC is read-only (`get,list,watch`, no secrets data, no write/exec); the cert is short-lived; the
  enrollment token is single-use; Secret `.data` is never collected or stored.
- The Helm method is unchanged and still works.
