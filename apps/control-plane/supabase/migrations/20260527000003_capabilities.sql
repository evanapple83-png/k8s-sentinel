-- Opt-in elevated capabilities per cluster (1F). The baseline agent is
-- read-only; admins may toggle extra capabilities, each of which surfaces a
-- kubectl/helm snippet to apply in-cluster. Every change is mirrored to the
-- audit log. Absence of a row means the capability is off (secure default).
create table if not exists cluster_capability (
  cluster_id  uuid not null references cluster(id) on delete cascade,
  key         text not null,
  enabled     boolean not null default false,
  updated_at  timestamptz not null default now(),
  updated_by  uuid references app_user(id) on delete set null,
  primary key (cluster_id, key)
);

alter table cluster_capability enable row level security;
