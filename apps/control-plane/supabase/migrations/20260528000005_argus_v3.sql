-- K8s Sentinel — hosted control-plane (Phase 5 / ARGUS v3 attack-graph fields).
--
-- Widens the existing finding/run schemas with the v3 attack-graph attributes
-- the in-cluster ARGUS engine emits at scan time, and adds a dedicated
-- `choke_point` table for the "apply this and N paths collapse" panel.
--
-- Every new column is NULLABLE so a pre-ARGUS agent (the legacy TS orchestrator
-- path, SENTINEL_SCANNER=builtin) keeps ingesting without breaking. Idempotent
-- — re-running the migration is safe (add-if-missing semantics).
--
-- Read-only by construction: nothing here lets the agent escalate; these
-- columns are normalized scan outputs streamed through the relay's trust
-- boundary. No secret material lands here (DATA-BOUNDARY.md).

-- ---------------------------------------------------------------------------
-- New enums for SSVC / confidence / exposure. `do $$ … $$` keeps the migration
-- idempotent the same way the init migration does.
-- ---------------------------------------------------------------------------
do $$ begin
  create type ssvc_decision as enum ('Act', 'Attend', 'Track', 'Track*');
exception when duplicate_object then null; end $$;

do $$ begin
  create type reach_confidence as enum ('high', 'medium', 'n/a');
exception when duplicate_object then null; end $$;

do $$ begin
  create type exposure_band as enum ('open', 'internal', 'small', 'cluster');
exception when duplicate_object then null; end $$;

-- ---------------------------------------------------------------------------
-- finding: v3 attributes (KEV / EPSS / SSVC / confidence / exposure / reaches)
-- ---------------------------------------------------------------------------
alter table finding add column if not exists cve         text;
alter table finding add column if not exists kev         boolean;
alter table finding add column if not exists ransomware  boolean;
alter table finding add column if not exists epss        numeric;   -- 0..1
alter table finding add column if not exists ssvc        ssvc_decision;
alter table finding add column if not exists confidence  reach_confidence;
alter table finding add column if not exists exposure    exposure_band;
alter table finding add column if not exists reaches     text[] default '{}';

-- Filter index for the "show me KEV-tagged findings only" dashboard chip —
-- partial because the vast majority of findings have kev=false/null.
create index if not exists finding_kev_idx on finding(run_id) where kev = true;
-- Same idea for the SSVC 'Act' band, which the v3 Overview screen pivots on.
create index if not exists finding_ssvc_act_idx on finding(run_id) where ssvc = 'Act';

-- ---------------------------------------------------------------------------
-- run: threat-intel catalog snapshot (drives the intel banner across the UI)
-- ---------------------------------------------------------------------------
alter table run add column if not exists intel_source     text;
alter table run add column if not exists intel_version    text;
alter table run add column if not exists intel_kev_count  integer;
alter table run add column if not exists intel_epss_count integer;

-- ---------------------------------------------------------------------------
-- choke_point: the v3 "apply first" panel. Distinct from `remediation`
-- because it carries graph-derived `breaks` + the explicit `targets[]` of
-- crown jewels the control eliminates. We ALSO mirror these into the legacy
-- `remediation` table from the agent so the existing Fixes screen keeps
-- rendering them — once the v3 dashboard panel ships, that mirror can be
-- retired and the wire frame shrinks.
-- ---------------------------------------------------------------------------
create table if not exists choke_point (
  id           text not null,
  run_id       text not null references run(id) on delete cascade,
  control      jsonb not null default '{}'::jsonb,
  breaks       integer not null default 0,
  total_paths  integer not null default 0,
  targets      text[] not null default '{}',
  severity     severity not null,
  description  text not null default '',
  priority     integer not null default 0,
  primary key (run_id, id)
);
create index if not exists choke_point_run_idx on choke_point(run_id, priority desc);

alter table choke_point enable row level security;
