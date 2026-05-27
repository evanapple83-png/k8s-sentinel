-- K8s Sentinel — hosted control-plane schema (Phase 5 / Hybrid mode).
--
-- Multi-tenant: Account → Membership(role) → Cluster → Run → Finding /
-- AttackPath / AuditEntry, plus short-lived InstallToken for onboarding.
--
-- AUTH MODEL: this app authenticates users with NextAuth (Google/Microsoft/
-- GitHub), NOT Supabase Auth — so there is no auth.uid() to drive RLS. The
-- Next.js server is the ONLY database client; it connects with the Supabase
-- SECRET key (server-only, never shipped to the browser) and enforces tenant
-- isolation in an application data layer (lib/data.ts) that always scopes by
-- the signed-in user's membership. RLS is enabled on every table as
-- defense-in-depth: with no anon/authenticated policies, a leaked publishable
-- key or direct Data API call sees zero rows. The secret key bypasses RLS by
-- design — tenant scoping lives in code, audited and tested.

-- ---------------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------------
do $$ begin
  create type role as enum ('viewer', 'approver', 'admin');
exception when duplicate_object then null; end $$;

do $$ begin
  create type cluster_status as enum ('pending', 'connected', 'disconnected');
exception when duplicate_object then null; end $$;

do $$ begin
  create type cluster_mode as enum ('hybrid', 'cluster-local');
exception when duplicate_object then null; end $$;

do $$ begin
  create type run_status as enum ('running', 'complete', 'failed');
exception when duplicate_object then null; end $$;

do $$ begin
  create type severity as enum ('critical', 'high', 'medium', 'low', 'info');
exception when duplicate_object then null; end $$;

-- ---------------------------------------------------------------------------
-- Users (mirrors the NextAuth identity; populated on sign-in)
-- ---------------------------------------------------------------------------
create table if not exists app_user (
  id          uuid primary key default gen_random_uuid(),
  email       text unique not null,
  name        text,
  image       text,
  created_at  timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Account (tenant) + membership
-- ---------------------------------------------------------------------------
create table if not exists account (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  slug        text unique not null,
  created_at  timestamptz not null default now()
);

create table if not exists membership (
  account_id    uuid not null references account(id) on delete cascade,
  user_id       uuid not null references app_user(id) on delete cascade,
  role          role not null default 'viewer',
  mfa_enrolled  boolean not null default false,
  created_at    timestamptz not null default now(),
  primary key (account_id, user_id)
);
create index if not exists membership_user_idx on membership(user_id);

-- ---------------------------------------------------------------------------
-- Cluster (one connected in-cluster agent)
-- ---------------------------------------------------------------------------
create table if not exists cluster (
  id            uuid primary key default gen_random_uuid(),
  account_id    uuid not null references account(id) on delete cascade,
  name          text not null,
  status        cluster_status not null default 'pending',
  mode          cluster_mode not null default 'hybrid',
  agent_version text,
  last_seen_at  timestamptz,
  connected_at  timestamptz,
  created_at    timestamptz not null default now()
);
create index if not exists cluster_account_idx on cluster(account_id);

-- ---------------------------------------------------------------------------
-- Install token (15-min, single-use, account-scoped). Stored as a hash only.
-- ---------------------------------------------------------------------------
create table if not exists install_token (
  id          uuid primary key default gen_random_uuid(),
  account_id  uuid not null references account(id) on delete cascade,
  token_hash  text unique not null,
  expires_at  timestamptz not null,
  used_at     timestamptz,
  used_by_cluster uuid references cluster(id) on delete set null,
  created_by  uuid references app_user(id) on delete set null,
  created_at  timestamptz not null default now()
);
create index if not exists install_token_account_idx on install_token(account_id);

-- ---------------------------------------------------------------------------
-- Run + the agent-streamed posture data (normalized findings only)
-- ---------------------------------------------------------------------------
create table if not exists run (
  id            text primary key,
  cluster_id    uuid not null references cluster(id) on delete cascade,
  status        run_status not null default 'running',
  engine        text not null default 'mock',
  used_fixtures boolean not null default false,
  finding_count integer not null default 0,
  path_count    integer not null default 0,
  risk_score    integer,
  summary       text,
  created_at    timestamptz not null default now()
);
create index if not exists run_cluster_idx on run(cluster_id, created_at desc);

create table if not exists finding (
  id             text not null,
  run_id         text not null references run(id) on delete cascade,
  source         text not null,
  rule_id        text not null,
  title          text not null,
  description    text not null default '',
  severity       severity not null,
  resource       jsonb not null default '{}'::jsonb,
  reachable      boolean,
  exploit_score  integer,
  attack_path_id text,
  controls       jsonb,
  base_score     numeric,
  primary key (run_id, id)
);

create table if not exists attack_path (
  id          text not null,
  run_id      text not null references run(id) on delete cascade,
  narrative   text not null,
  score       integer not null,
  entry_point text,
  steps       jsonb not null default '[]'::jsonb,
  finding_ids text[] not null default '{}',
  primary key (run_id, id)
);

-- ---------------------------------------------------------------------------
-- Audit log (append-only mirror of the in-cluster immutable log)
-- ---------------------------------------------------------------------------
create table if not exists audit_entry (
  id          uuid primary key default gen_random_uuid(),
  account_id  uuid not null references account(id) on delete cascade,
  cluster_id  uuid references cluster(id) on delete set null,
  run_id      text,
  seq         bigint,
  ts          timestamptz not null default now(),
  actor       text not null,
  agent       text,
  action      text not null,
  detail      jsonb
);
create index if not exists audit_account_idx on audit_entry(account_id, ts desc);

-- ---------------------------------------------------------------------------
-- RLS — enable on every table. No anon/authenticated policies: the browser
-- never connects to Supabase directly, and the server uses the secret key
-- (which bypasses RLS). This makes any leaked publishable key / direct Data
-- API call return zero rows. Tenant scoping is enforced in lib/data.ts.
-- ---------------------------------------------------------------------------
alter table app_user      enable row level security;
alter table account       enable row level security;
alter table membership    enable row level security;
alter table cluster       enable row level security;
alter table install_token enable row level security;
alter table run           enable row level security;
alter table finding       enable row level security;
alter table attack_path   enable row level security;
alter table audit_entry   enable row level security;
