'use server';

import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';
import { supabaseAdmin, supabaseConfigured } from '@/lib/supabase/server';
import { requireMembership, requireRole } from '@/lib/data';
import { helmInstallCommand, mintInstallToken } from '@/lib/install-tokens';

export type GenerateResult =
  | { ok: true; command: string; expiresAt: string }
  | { ok: false; reason: 'demo' | 'forbidden' | 'no-account' };

/** Mint a fresh install token (admin only) and return the copy-paste command. */
export async function generateInstall(): Promise<GenerateResult> {
  if (!authEnabled() || !supabaseConfigured()) return { ok: false, reason: 'demo' };
  const session = await auth();
  const userId = session?.user?.id;
  const accountId = session?.user?.activeAccountId;
  if (!userId || !accountId) return { ok: false, reason: 'no-account' };

  try {
    const { token, expiresAt } = await mintInstallToken(
      userId,
      accountId,
      session.user.email ?? 'user',
    );
    return { ok: true, command: helmInstallCommand(token), expiresAt };
  } catch {
    return { ok: false, reason: 'forbidden' };
  }
}

export type PollResult =
  | { connected: true; cluster: { id: string; name: string; connectedAt: string | null } }
  | { connected: false };

/** Poll for a freshly connected cluster in the active account (onboarding wait). */
export async function pollConnection(): Promise<PollResult> {
  if (!authEnabled() || !supabaseConfigured()) return { connected: false };
  const session = await auth();
  const userId = session?.user?.id;
  const accountId = session?.user?.activeAccountId;
  if (!userId || !accountId) return { connected: false };

  await requireMembership(userId, accountId);
  const db = supabaseAdmin();
  const { data } = await db
    .from('cluster')
    .select('id, name, connected_at, status')
    .eq('account_id', accountId)
    .eq('status', 'connected')
    .order('connected_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!data) return { connected: false };
  return {
    connected: true,
    cluster: { id: data.id, name: data.name, connectedAt: data.connected_at ?? null },
  };
}

export type ScanTriggerResult = { ok: true; runId?: string } | { ok: false; reason: string };

/**
 * Trigger a scan on a connected cluster via the relay's HTTP command bridge.
 * The relay forwards it down the tunnel to the agent and returns the result;
 * the posture lands back over the ingest webhook. Approver+ only.
 */
export async function triggerScan(clusterId: string): Promise<ScanTriggerResult> {
  if (!authEnabled() || !supabaseConfigured()) return { ok: false, reason: 'demo' };
  const session = await auth();
  const userId = session?.user?.id;
  const accountId = session?.user?.activeAccountId;
  if (!userId || !accountId) return { ok: false, reason: 'no-account' };

  try {
    await requireRole(userId, accountId, 'approver');
  } catch {
    return { ok: false, reason: 'forbidden' };
  }

  const db = supabaseAdmin();
  const { data: cluster } = await db
    .from('cluster')
    .select('id')
    .eq('id', clusterId)
    .eq('account_id', accountId)
    .maybeSingle();
  if (!cluster) return { ok: false, reason: 'not-found' };

  const relayUrl = (process.env.RELAY_HTTP_URL ?? '').replace(/\/+$/, '');
  const secret = process.env.RELAY_CONTROL_SECRET;
  if (!relayUrl || !secret) return { ok: false, reason: 'relay-not-configured' };

  try {
    const res = await fetch(`${relayUrl}/command`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${secret}` },
      body: JSON.stringify({ clusterId, kind: 'scan' }),
    });
    const body = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string; data?: { runId?: string } };
    if (!res.ok || body.ok === false) return { ok: false, reason: body.error ?? `relay ${res.status}` };
    return { ok: true, runId: body.data?.runId };
  } catch {
    return { ok: false, reason: 'relay-unreachable' };
  }
}
