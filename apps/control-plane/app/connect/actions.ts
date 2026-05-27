'use server';

import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';
import { supabaseAdmin, supabaseConfigured } from '@/lib/supabase/server';
import { requireMembership } from '@/lib/data';
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
