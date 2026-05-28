# Public-key connect — wire contract (locked, both agents read this)

> Authoritative shapes the control-plane API speaks AND the `argus bootstrap csr`
> CLI must honour. Lives outside any one language so the backend (TS) and the
> CLI (Python) converge on the same bytes.
>
> Feature-flag: `FEATURE_PUBKEY_CONNECT` (env, defaults `false` everywhere).
> When the flag is false the new screens render nothing and the new API routes
> return `404`. The existing Helm flow is unchanged either way.

## 0. Enrollment token

A single-use, short-TTL bearer credential that ties one `argus bootstrap csr`
run to one pending cluster row.

```
Format:    "ent_" + base64url(32 random bytes)            # 47 chars total
TTL:       15 minutes
Storage:   sha-256 hex of the raw token in cluster_enrollment.token_hash
           (the raw value is shown ONCE in the API response and never again)
Usage:     Authorization: Bearer ent_…   on every event + scan POST
Lifecycle: marked used_at on first scan_pushed event; subsequent calls 401
```

## 1. Cluster + enrollment

```
POST /api/clusters                       (auth: signed-in session)
Body: { "name": "<human label>", "method": "helm" | "pubkey" }
200:  {
  "id": "<uuid>",                        // cluster.id, also used as clusterId
  "enrollmentToken": "ent_...",          // raw, single-use, 15 min TTL
  "expiresAt": "2026-05-28T14:15:00Z",
  "method": "helm" | "pubkey",
  "commands": {                          // pre-rendered for the UI
    "helm":  "helm install sentinel deploy/helm --set …",
    "pubkey":"argus bootstrap csr --enroll ent_… --control-plane https://…"
  }
}
```

```
GET /api/clusters/:id                    (auth: signed-in session, must own)
200:  {
  "id": "<uuid>",
  "name": "...",
  "method": "helm" | "pubkey",
  "status": "<ClusterStatus>",
  "events": [ <ConnectionEvent>, ... ],  // ordered by ts ascending
  "lastScanId": "<uuid>" | null,
  "createdAt": "...",
  "expiresAt": "..."                     // enrollment expiry, not cluster
}
```

`ClusterStatus` (enum):
- `pending`             — created, no CLI activity yet (default)
- `cli_started`         — pubkey: bootstrap CLI ran first event
- `csr_submitted`       — pubkey: CSR object exists in the cluster
- `awaiting_approval`   — pubkey: CSR pending admin approve
- `approved`            — pubkey: cert issued, RBAC bound
- `connected`           — first scan received (terminal happy state)
- `failed`              — terminal error; `events[].detail.error` carries why
- `expired`             — enrollment token TTL passed without `connected`

## 2. Connection events

```
POST /api/clusters/:id/events           (auth: Bearer enrollment token)
Body: {
  "type": "<EventType>",
  "detail": { ... }                     // bounded; <= 2048 bytes JSON
}
204
```

`EventType` (enum, append-only):

| Type                  | Emitted by   | `detail` payload                                                                    |
| --------------------- | ------------ | ----------------------------------------------------------------------------------- |
| `agent_registered`    | Helm agent   | `{ agentVersion?: string }`                                                         |
| `cli_started`         | Pubkey CLI   | `{ argusVersion?: string, platform?: string }`                                      |
| `csr_submitted`       | Pubkey CLI   | `{ csrName: string, ttlSeconds: number }`                                           |
| `awaiting_approval`   | Pubkey CLI   | `{ csrName: string, approveCommand: string }`                                       |
| `approved`            | Pubkey CLI   | `{ csrName: string }`                                                               |
| `rbac_bound`          | Pubkey CLI   | `{ clusterRole: string, clusterRoleBinding: string, subject: { cn: string, o: string } }` |
| `scan_pushed`         | Both         | `{ scanId: string, findingCount: number, riskScore: number \| null }`               |
| `error`               | Both         | `{ stage: string, message: string }`                                                |

Detail bodies above are minimum shapes; extra keys are stored verbatim but
must keep the whole frame ≤ 2 KB.

The control-plane reduces events → `ClusterStatus` deterministically:
- any `error` after `connected` is ignored for status (but still stored)
- `connected` is sticky once reached
- status mapping: `cli_started` → `cli_started`; `csr_submitted` → `csr_submitted`;
  `awaiting_approval` → `awaiting_approval`; `approved` + `rbac_bound` → `approved`;
  `scan_pushed` → `connected`; `error` → `failed`.

## 3. Scan push

```
POST /api/scans                         (auth: Bearer enrollment token)
Body: {
  "clusterId": "<uuid>",                // must match the token's cluster
  "report": <v3 engine report>          // exactly the JSON ARGUS emits
}
201:  { "scanId": "<uuid>", "createdAt": "..." }
```

`<v3 engine report>` is the **unmodified** JSON the Python pipeline writes to
`out/report.json` (see `apps/api/src/tunnel/argus.ts` `ArgusReportJson` for the
canonical shape: `cluster, scannedAt, riskScore, intel, reachableJewels[],
paths{}, chokePoints[], findings[], acceptedRisks[], refusals[], autoReopened[],
workloads[], activeFindings[], metadata{}`).

Control-plane side-effects:
1. Insert `scans` row `{ id, cluster_id, created_at, report }`.
2. Run the existing `ingestSnapshot(clusterId, …)` flow so `run` / `finding` /
   `attack_path` / `choke_point` / `audit_entry` populate too — that's what the
   existing Overview / Findings / Fixes / Paths screens already read.
3. Emit a synthetic `scan_pushed` event with `{ scanId, findingCount, riskScore }`.
4. Flip cluster.status → `connected`; mark enrollment token `used_at` if first scan.

## 4. Auth

- `Authorization: Bearer ent_<raw>` on every CLI → API call (events + scans).
- Server resolves: `sha256(raw)` → match `cluster_enrollment.token_hash`,
  reject if `expires_at < now`, reject if `used_at` set AND incoming type is not
  an idempotent re-post of `scan_pushed` for the same `clusterId`. All in
  constant-time compare.
- Signed-in users use the existing NextAuth session; tenant scoping via
  `lib/data.ts` `requireMembership`.

## 5. Storage (Supabase migration 0006)

```
cluster_enrollment (
  id                  uuid pk,
  cluster_id          uuid not null fk → cluster(id) on delete cascade,
  account_id          uuid not null fk → account(id) on delete cascade,
  method              text not null check (method in ('helm','pubkey')),
  token_hash          text unique not null,
  expires_at          timestamptz not null,
  used_at             timestamptz,
  created_by          uuid fk → app_user(id),
  created_at          timestamptz not null default now()
)

connection_event (
  id          uuid pk,
  cluster_id  uuid not null fk → cluster(id) on delete cascade,
  type        text not null,                   -- one of EventType above
  detail      jsonb not null default '{}',
  ts          timestamptz not null default now()
)
create index on connection_event (cluster_id, ts);

scans (
  id          uuid pk,
  cluster_id  uuid not null fk → cluster(id) on delete cascade,
  report      jsonb not null,                  -- full v3 report
  created_at  timestamptz not null default now()
)
create index on scans (cluster_id, created_at desc);
```

RLS enabled on all three (no policies — server-side secret key bypass, matches
the existing pattern).

## 6. Feature flag

```
process.env.FEATURE_PUBKEY_CONNECT === '1' | 'true' | 'on'
```

- API routes: when off, return 404 — endpoint truly not exposed.
- UI: when off, `/connect` renders the helm-only single-method view (current
  behaviour). When on, the segmented toggle appears.
- CLI: not flagged — only enabled when called from a `pubkey`-method
  enrollment token, which only the flagged UI/API can mint.

## 7. RBAC for the pubkey identity

Exact same `ClusterRole` as Helm: `get,list,watch` across the read-only resource
set (pods, deployments, statefulsets, daemonsets, services, ingresses,
networkpolicies, serviceaccounts, roles, rolebindings, clusterroles,
clusterrolebindings, configmaps, namespaces, nodes, persistentvolumes,
persistentvolumeclaims, replicationcontrollers, jobs, cronjobs,
poddisruptionbudgets, customresourcedefinitions). **Zero `secrets` verbs.**

Subject: the cert's `subject.commonName` (CN) AND `subject.organization` (O).
Bind name: `argus-readonly-<clusterId-short>`.

## 8. Definition of locked

Once both agents start, this contract is **frozen for the duration of their
runs**. If either needs to deviate, surface it in their final report; the
integrating step (main agent) decides whether to amend the contract + re-run
the other side.
