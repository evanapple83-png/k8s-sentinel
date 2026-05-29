import 'server-only';
import { createHash, randomBytes } from 'node:crypto';
import { supabaseAdmin } from './supabase/server';
import { recordAudit, requireRole } from './data';
import { chartOciRef, chartVersion } from './chart';
import type { Cluster } from './types';

/**
 * Install tokens (BUILD.md: hybrid onboarding). A short-lived, single-use,
 * account-scoped secret embedded in the copy-paste Helm command. The in-cluster
 * agent exchanges it on first boot to register its cluster (and, in fase 2, to
 * receive its mTLS client cert from the relay). Only a SHA-256 hash is stored.
 */

const TTL_MS = 15 * 60 * 1000; // 15 minutes

function hash(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

export interface MintedToken {
  token: string; // shown once
  expiresAt: string;
}

/** Mint a token for an account. Admin-only (throws AccessError otherwise). */
export async function mintInstallToken(
  userId: string,
  accountId: string,
  actorEmail: string,
): Promise<MintedToken> {
  await requireRole(userId, accountId, 'admin');
  const token = `sk-install-${randomBytes(24).toString('base64url')}`;
  const expiresAt = new Date(Date.now() + TTL_MS).toISOString();

  const db = supabaseAdmin();
  const { error } = await db.from('install_token').insert({
    account_id: accountId,
    token_hash: hash(token),
    expires_at: expiresAt,
    created_by: userId,
  });
  if (error) throw error;

  await recordAudit({
    accountId,
    actor: actorEmail,
    action: 'install_token.minted',
    detail: { expiresAt },
  });
  return { token, expiresAt };
}

export interface RegisterResult {
  clusterId: string;
  accountId: string;
  runId: string;
}

/**
 * Exchange a raw install token for a registered cluster. Called by the agent on
 * first boot — authenticated solely by possession of the (unguessable) token,
 * so this performs its own validation and is NOT behind the user session.
 * Auto-kicks a first scan (a placeholder run; real results stream in via the
 * relay in fase 2).
 */
export async function consumeInstallToken(
  rawToken: string,
  meta: { agentVersion?: string; clusterName?: string },
): Promise<RegisterResult> {
  const db = supabaseAdmin();
  const { data: tok, error } = await db
    .from('install_token')
    .select('id, account_id, expires_at, used_at')
    .eq('token_hash', hash(rawToken))
    .maybeSingle();
  if (error) throw error;
  if (!tok) throw new TokenError('invalid install token');
  if (tok.used_at) throw new TokenError('install token already used');
  if (new Date(tok.expires_at).getTime() < Date.now()) throw new TokenError('install token expired');

  // Create the cluster (connected) for the token's account.
  const { data: cluster, error: cErr } = await db
    .from('cluster')
    .insert({
      account_id: tok.account_id,
      name: meta.clusterName?.trim() || 'my-cluster',
      status: 'connected',
      mode: 'hybrid',
      agent_version: meta.agentVersion ?? null,
      last_seen_at: new Date().toISOString(),
      connected_at: new Date().toISOString(),
    })
    .select('id')
    .single();
  if (cErr) throw cErr;

  // Single-use: mark consumed and bind to the new cluster.
  await db
    .from('install_token')
    .update({ used_at: new Date().toISOString(), used_by_cluster: cluster.id })
    .eq('id', tok.id);

  // Auto-trigger first scan — placeholder run; the agent streams real findings
  // up through the relay (fase 2). Stable, sortable id.
  const runId = `run-${Date.now()}`;
  await db.from('run').insert({
    id: runId,
    cluster_id: cluster.id,
    status: 'running',
    engine: 'claude',
  });

  await recordAudit({
    accountId: tok.account_id,
    actor: 'agent',
    action: 'cluster.registered',
    clusterId: cluster.id,
    runId,
    detail: { agentVersion: meta.agentVersion ?? null, autoScan: true },
  });

  return { clusterId: cluster.id, accountId: tok.account_id, runId };
}

/** Cluster status for the onboarding poll (tenant-scoped to the caller). */
export async function getClusterStatus(
  userId: string,
  accountId: string,
  clusterId: string,
): Promise<Pick<Cluster, 'id' | 'status' | 'agentVersion' | 'connectedAt'> | null> {
  await requireRole(userId, accountId, 'viewer');
  const db = supabaseAdmin();
  const { data } = await db
    .from('cluster')
    .select('id, status, agent_version, connected_at')
    .eq('id', clusterId)
    .eq('account_id', accountId)
    .maybeSingle();
  if (!data) return null;
  return {
    id: data.id,
    status: data.status,
    agentVersion: data.agent_version ?? null,
    connectedAt: data.connected_at ?? null,
  };
}

/** The single copy-paste Helm command, with the token embedded. */
export function helmInstallCommand(token: string): string {
  const relay = process.env.RELAY_URL ?? 'wss://relay.k8s-sentinel.example';
  return [
    `helm install sentinel ${chartOciRef()} \\`,
    `  --version ${chartVersion()} \\`,
    '  --namespace sentinel --create-namespace \\',
    '  --set mode=hybrid \\',
    `  --set relay.url=${relay} \\`,
    `  --set relay.installToken=${token}`,
  ].join('\n');
}

export class TokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TokenError';
  }
}
