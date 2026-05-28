'use server';

import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';
import { supabaseConfigured } from '@/lib/supabase/server';
import { FEATURE_PUBKEY_CONNECT } from '@/lib/flags';
import { AccessError } from '@/lib/data';
import { createClusterEnrollment, getClusterDetail, type ClusterDetail } from '@/lib/pubkey-connect';

/**
 * Server actions for the Public-key tab of /connect.
 *
 * Mirrors the shape of ./actions.ts (the existing Helm tab) but uses the
 * pubkey-connect data layer. Both `generatePubkeyEnrollment` and `pollCluster`
 * fail closed when FEATURE_PUBKEY_CONNECT is off — the client guards too, but
 * this is the trust boundary.
 *
 * The raw enrollment token leaves this process only via the action return —
 * never logged, never persisted in any form except the sha256 hash already
 * written by createClusterEnrollment.
 */

export type GeneratePubkeyResult =
  | {
      ok: true;
      clusterId: string;
      command: string;
      rawToken: string; // shown once in the UI; the client never persists it
      expiresAt: string;
    }
  | { ok: false; reason: 'disabled' | 'demo' | 'no-account' | 'forbidden' | 'error' };

export async function generatePubkeyEnrollment(
  name = 'my-cluster',
): Promise<GeneratePubkeyResult> {
  if (!FEATURE_PUBKEY_CONNECT) return { ok: false, reason: 'disabled' };
  if (!authEnabled() || !supabaseConfigured()) return { ok: false, reason: 'demo' };

  const session = await auth();
  const userId = session?.user?.id;
  const accountId = session?.user?.activeAccountId;
  if (!userId || !accountId) return { ok: false, reason: 'no-account' };

  try {
    const out = await createClusterEnrollment({
      userId,
      accountId,
      name,
      method: 'pubkey',
    });
    return {
      ok: true,
      clusterId: out.id,
      command: out.methodCommands.pubkey,
      rawToken: out.rawToken,
      expiresAt: out.expiresAt,
    };
  } catch (err) {
    if (err instanceof AccessError) return { ok: false, reason: 'forbidden' };
    console.error('[generatePubkeyEnrollment] failed:', err);
    return { ok: false, reason: 'error' };
  }
}

export type PollClusterResult =
  | { ok: true; detail: ClusterDetail }
  | { ok: false; reason: 'disabled' | 'demo' | 'no-account' | 'forbidden' | 'not-found' | 'error' };

/**
 * Poll one cluster's detail (status + events + lastScanId). Called every ~3s
 * by the pubkey tab so the stepper advances live. Returns the same shape as
 * GET /api/clusters/:id but goes through the existing session — no extra
 * fetch from the browser.
 */
export async function pollCluster(clusterId: string): Promise<PollClusterResult> {
  if (!FEATURE_PUBKEY_CONNECT) return { ok: false, reason: 'disabled' };
  if (!authEnabled() || !supabaseConfigured()) return { ok: false, reason: 'demo' };

  const session = await auth();
  const userId = session?.user?.id;
  const accountId = session?.user?.activeAccountId;
  if (!userId || !accountId) return { ok: false, reason: 'no-account' };

  try {
    const detail = await getClusterDetail(userId, accountId, clusterId);
    if (!detail) return { ok: false, reason: 'not-found' };
    return { ok: true, detail };
  } catch (err) {
    if (err instanceof AccessError) return { ok: false, reason: 'forbidden' };
    console.error('[pollCluster] failed:', err);
    return { ok: false, reason: 'error' };
  }
}
