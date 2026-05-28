-- K8s Sentinel — hosted control-plane (Phase 5 / Public-key connect).
--
-- Adds the storage backing the new "Public key" connect method (and a
-- shared event timeline that the existing Helm flow can also feed).
-- See docs/PUBKEY_CONNECT_CONTRACT.md §5 — these tables are the wire-
-- contract source of truth.
--
-- All gated behind FEATURE_PUBKEY_CONNECT in the API/UI layer; the schema
-- itself is harmless when the flag is off (no triggers, no policies, no
-- side-effects on existing rows). Idempotent (`if not exists`) so a
-- re-run is safe.
--
-- RLS: enabled, NO policies — matches the existing pattern. The Next.js
-- server is the only DB client; it uses the SECRET key (bypasses RLS) and
-- scopes by membership in lib/data.ts. A leaked publishable key sees zero
-- rows.

-- ---------------------------------------------------------------------------
-- cluster_enrollment: short-TTL bearer token tying ONE `argus bootstrap csr`
-- (or one helm install) run to ONE pending cluster row. Token is stored only
-- as sha256 hex; the raw value leaves /api/clusters exactly once.
-- ---------------------------------------------------------------------------
create table if not exists cluster_enrollment (
  id          uuid primary key default gen_random_uuid(),
  cluster_id  uuid not null references cluster(id) on delete cascade,
  account_id  uuid not null references account(id) on delete cascade,
  method      text not null check (method in ('helm', 'pubkey')),
  token_hash  text unique not null,
  expires_at  timestamptz not null,
  used_at     timestamptz,
  created_by  uuid references app_user(id) on delete set null,
  created_at  timestamptz not null default now()
);
create index if not exists cluster_enrollment_cluster_idx
  on cluster_enrollment(cluster_id);
create index if not exists cluster_enrollment_account_idx
  on cluster_enrollment(account_id);

-- ---------------------------------------------------------------------------
-- connection_event: append-only timeline of progress emitted by the CLI/agent
-- as it walks the enrollment flow. Drives the UI status stepper. `type` is a
-- free text column (no enum) because the contract treats EventType as
-- append-only — adding values shouldn't need a schema migration.
-- ---------------------------------------------------------------------------
create table if not exists connection_event (
  id          uuid primary key default gen_random_uuid(),
  cluster_id  uuid not null references cluster(id) on delete cascade,
  type        text not null,
  detail      jsonb not null default '{}'::jsonb,
  ts          timestamptz not null default now()
);
create index if not exists connection_event_cluster_idx
  on connection_event(cluster_id, ts);

-- ---------------------------------------------------------------------------
-- scans: the raw v3 engine report pushed by `argus bootstrap csr`. Kept as a
-- jsonb blob so the wire shape can evolve without a migration; the existing
-- ingestSnapshot() call still populates run/finding/attack_path/choke_point so
-- the Overview/Findings/Fixes screens render unchanged.
-- ---------------------------------------------------------------------------
create table if not exists scans (
  id          uuid primary key default gen_random_uuid(),
  cluster_id  uuid not null references cluster(id) on delete cascade,
  report      jsonb not null,
  created_at  timestamptz not null default now()
);
create index if not exists scans_cluster_idx
  on scans(cluster_id, created_at desc);

-- ---------------------------------------------------------------------------
-- RLS: enable, no policies (defense-in-depth — see init migration §RLS).
-- ---------------------------------------------------------------------------
alter table cluster_enrollment enable row level security;
alter table connection_event   enable row level security;
alter table scans              enable row level security;
