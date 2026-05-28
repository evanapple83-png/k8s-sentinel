-- AI narration conversation state (Ask sidebar — spec §4 + §5).
--
-- One row per conversation turn (user or assistant). Conversation id is
-- client-minted on first POST /api/ai/ask of a fresh thread; the dashboard
-- resets it on cluster change so two clusters can't bleed history into each
-- other's prompts. Ord is the strict insertion order within the conversation
-- and lets us reconstruct messages without relying on created_at clock skew.
--
-- account_id + cluster_id are duplicated onto every turn so the audit-log
-- viewer can join (or, more simply, scope by tenant without a hop through
-- the cluster table when clusters get deleted).

create table if not exists ai_conversation_turn (
  conversation_id  uuid not null,
  ord              integer not null,
  account_id       uuid not null references account(id) on delete cascade,
  user_id          uuid references app_user(id) on delete set null,
  cluster_id       uuid references cluster(id) on delete set null,
  role             text not null check (role in ('user', 'assistant')),
  content          text not null,
  created_at       timestamptz not null default now(),
  primary key (conversation_id, ord)
);
create index if not exists ai_conversation_turn_account_idx
  on ai_conversation_turn(account_id, conversation_id, ord);

alter table ai_conversation_turn enable row level security;
