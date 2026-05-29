-- Durable agent reconnect credential (issue #11).
--
-- Hybrid agents bootstrap with a single-use install token. Before this, every
-- reconnect re-sent that consumed token and was rejected, so an agent could not
-- survive a tunnel drop. We now mint a cluster-bound reconnect token on first
-- registration and store ONLY its sha256 hash here; the agent replays the raw
-- value (with its clusterId) on reconnect. Not single-use; validated in code.
alter table cluster add column if not exists reconnect_token_hash text;

comment on column cluster.reconnect_token_hash is
  'sha256 hex of the durable agent reconnect token (issue #11). Null until first registration.';
