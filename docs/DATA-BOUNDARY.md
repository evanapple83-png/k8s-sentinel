# Data boundary

What leaves your cluster, what never does, and how the connection is secured.
This is the contract behind K8s Sentinel's two deployment modes.

> **Principle:** the agent is **read-only by default**, **proposes** fixes
> (never applies them), logs **everything**, and only ever sends a cluster's
> **normalized security posture** upstream — never its secrets, credentials, or
> raw contents.

---

## Hybrid mode (default)

The agent runs **inside your cluster**; the web UI is hosted by us. The agent
dials **out** to the relay — there is no inbound port, Ingress, or port-forward.

### ✅ Leaves the cluster (flows up to the hosted control plane)

- **Normalized findings** — scanner-agnostic records: source (Trivy/Kubescape/
  kube-bench/Falco), rule/CVE id, title, description, severity, and a resource
  reference (kind, name, namespace, image tag). All scanner text is sanitized
  in-cluster before it is sent.
- **Attack paths** — the correlated narratives and the finding ids they link.
- **Run metadata** — scan timestamps, engine used, finding/path counts, the
  posture risk score, and the summary line.
- **Inventory summary** — workload/service/namespace **names**, image
  references, and **RBAC structure** (which roles bind to which subjects) needed
  to reason about reachability.
- **Audit entries** — every agent decision and every permission change.
- **Cluster identity** — a cluster name, agent version, and liveness heartbeat.

### ⛔ Never leaves the cluster

- **Secret values / data.** The baseline ClusterRole can `list` secret names and
  metadata only — it cannot read secret contents. The Analyst reasons about the
  *reachability* of a secret, never its value.
- **Raw manifests / full resource specs** beyond the fields captured in a finding.
- **Pod logs, container filesystems, image layers.**
- **The kubeconfig, ServiceAccount tokens, or any cluster credential.**
- Anything the read-only ClusterRole cannot read (see the in-app **Permissions**
  screen for the exact, plain-English list).

### How the connection is secured

- The agent opens a single **outbound mTLS** (TLS 1.3) tunnel to the relay over
  443. No inbound exposure.
- On first boot the agent exchanges a **15-minute, single-use install token**
  for a per-cluster client certificate (auto-rotated). The token is stored only
  as a SHA-256 hash and is bound to one account.
- The relay is **stateless** and forwards traffic between the control plane and
  the correct cluster agent. **No plaintext payloads are persisted** on it.

### Where hosted data lives

- In a tenant-isolated Postgres database (Supabase). Every row is scoped to an
  account; access is enforced both in the application data layer and by
  row-level security.
- **Deletion:** disconnecting a cluster removes its runs, findings, paths, and
  capability settings; deleting an account cascades to everything it owns.

---

## Cluster-local / air-gap mode (Hermes)

For disconnected, classified, or data-residency-constrained environments.

- The UI is served **inside your cluster**; **nothing leaves it.**
- Inference runs on a **local open-weight model** (Hermes) with **zero external
  calls** — the egress NetworkPolicy permits only DNS + in-cluster traffic.
- No relay, no hosted database, no install token. Same agents, same read-only
  RBAC, same audit log.

Switch with one Helm flag: `--set engine.kind=hermes` (see `deploy/helm`).

---

## What's the same in both modes

- **Read-only by default.** Elevated capabilities are **opt-in and audited** via
  the Permissions screen; each emits a copy-paste command you apply yourself.
- **Propose, don't apply.** Remediations are reviewable diffs/PRs — the agent
  never mutates your cluster.
- **Full audit trail.** Every decision and permission change is recorded in an
  immutable, hash-chained log.
