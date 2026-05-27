'use server';

import { revalidatePath } from 'next/cache';
import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';
import { supabaseConfigured } from '@/lib/supabase/server';
import { setCapability } from '@/lib/permissions';

export type ToggleResult = { ok: true } | { ok: false; reason: 'demo' | 'forbidden' | 'no-account' };

/** Toggle an elevated capability for a cluster (admin only). Audited. */
export async function toggleCapability(
  clusterId: string,
  key: string,
  enabled: boolean,
): Promise<ToggleResult> {
  if (!authEnabled() || !supabaseConfigured()) return { ok: false, reason: 'demo' };
  const session = await auth();
  const userId = session?.user?.id;
  const accountId = session?.user?.activeAccountId;
  if (!userId || !accountId) return { ok: false, reason: 'no-account' };

  try {
    await setCapability(userId, accountId, clusterId, key, enabled, session.user.email ?? 'user');
    revalidatePath('/permissions');
    return { ok: true };
  } catch {
    return { ok: false, reason: 'forbidden' };
  }
}
