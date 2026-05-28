-- K8s Sentinel — control-plane (AI narration layer audit + rate-limit storage).
--
-- Build-step 1 of docs/AI_NARRATION_SPEC.md: the persistence layer for the new
-- /api/ai/* endpoints. Behind FEATURE_AI_NARRATION; the endpoints return 404
-- when the flag is off, but the tables are additive + idempotent so applying
-- the migration ahead of the flag flip is safe.
--
-- Two tables:
--   * ai_audit       — append-only audit row per model call (spec §6). 90+ day
--                      retention; this is what we show Anthropic if the
--                      CVP use-case fit ever needs review.
--   * ai_rate_window — sliding-window counters for per-user + per-workspace
--                      rate limits + cost cap (spec §6). Tiny rows, indexed by
--                      (subject, bucket_start) for the cheapest possible
--                      "how many calls in the last minute" query.

-- ---------------------------------------------------------------------------
-- ai_audit
-- ---------------------------------------------------------------------------
create table if not exists ai_audit (
  id            uuid primary key default gen_random_uuid(),
  account_id    uuid not null references account(id) on delete cascade,
  user_id       uuid references app_user(id) on delete set null,
  cluster_id    uuid references cluster(id) on delete set null,
  scan_id       uuid references scans(id) on delete set null,
  endpoint      text not null,                  -- 'explain-finding' | 'explain-path' | 'explain-fix' | 'ask'
  model         text not null,                  -- e.g. 'claude-sonnet-4-6'
  target_kind   text,                           -- 'finding' | 'path' | 'fix' | 'ask'
  target_id     text,                           -- finding id / path target / chokepoint index / question hash
  prompt_hash   text not null,                  -- sha256(system + report + user-turn)
  -- Token accounting (spec §6 + the prompt-caching skill — track cache hit rate explicitly).
  input_tokens                  integer not null default 0,
  output_tokens                 integer not null default 0,
  cache_creation_input_tokens   integer not null default 0,
  cache_read_input_tokens       integer not null default 0,
  -- Money (USD micro-cents = $ × 1_000_000). Computed server-side from
  -- token counts + the per-model price table; stored so the cost cap query
  -- is a simple sum.
  cost_microcents               integer not null default 0,
  status        text not null,                  -- 'ok' | 'refused' | 'error' | 'rate_limited' | 'cost_capped'
  error_message text,                           -- populated when status != 'ok'
  output_text   text,                           -- the model's response (capped server-side)
  has_citation_warning boolean not null default false,
  created_at    timestamptz not null default now()
);
create index if not exists ai_audit_account_idx on ai_audit(account_id, created_at desc);
create index if not exists ai_audit_user_idx    on ai_audit(user_id, created_at desc);
create index if not exists ai_audit_cluster_idx on ai_audit(cluster_id, created_at desc);

alter table ai_audit enable row level security;

-- ---------------------------------------------------------------------------
-- ai_rate_window — minute + day + month buckets for rate-limit + cost cap.
-- ---------------------------------------------------------------------------
-- We don't bother with a real sliding window — the bucket-counter pattern is
-- O(1) per request and accurate enough at the resolutions the spec asks for
-- (per-min per-user, per-day per-workspace, per-month per-workspace cost cap).
-- bucket_kind ∈ ('user_minute', 'account_day', 'account_month_cost').
-- For the first two: `count` is # of requests; cost_microcents is 0.
-- For the last:      `count` is # of requests; cost_microcents is the sum.
-- ---------------------------------------------------------------------------
create table if not exists ai_rate_window (
  bucket_kind     text not null,                 -- see above
  subject_id      text not null,                 -- user.id (uuid as text) or account.id
  bucket_start    timestamptz not null,          -- truncated to minute / day / month start
  count           integer not null default 0,
  cost_microcents bigint not null default 0,
  updated_at      timestamptz not null default now(),
  primary key (bucket_kind, subject_id, bucket_start)
);

alter table ai_rate_window enable row level security;

-- Convenience: a per-bucket-kind expiry hint (TTL-style cleanup is left to a
-- nightly job — buckets older than 35 days for minute/day, 13 months for cost
-- can be safely dropped by `delete from ai_rate_window where …`).
