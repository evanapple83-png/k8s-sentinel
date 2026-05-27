-- K8s Sentinel — hosted control-plane (Phase 5 / fase 2: live ingest).
--
-- Remediation proposals streamed up from the agent alongside findings/paths.
-- Propose-only by definition: these are reviewable diffs / PR bodies, never
-- anything the platform applies. Scoped to a run (cascades on run delete);
-- RLS enabled with no policies, like every other table (lib/data.ts enforces
-- tenant isolation, the secret-key server client bypasses RLS by design).

create table if not exists remediation (
  id             text not null,
  run_id         text not null references run(id) on delete cascade,
  playbook_id    text not null,
  title          text not null,
  severity       severity not null,
  kind           text not null,
  rationale      text not null default '',
  path           text not null default '',
  diff           text not null default '',
  manual_steps   jsonb not null default '[]'::jsonb,
  controls       jsonb not null default '[]'::jsonb,
  finding_ids    text[] not null default '{}',
  attack_path_id text,
  priority       integer not null default 0,
  branch         text not null default '',
  pr_title       text not null default '',
  pr_body        text not null default '',
  primary key (run_id, id)
);
create index if not exists remediation_run_idx on remediation(run_id);

alter table remediation enable row level security;
