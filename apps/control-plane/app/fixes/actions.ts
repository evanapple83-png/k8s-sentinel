'use server';

import { revalidatePath } from 'next/cache';
import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';
import { supabaseConfigured } from '@/lib/supabase/server';
import { AccessError, recordAudit, requireRole } from '@/lib/data';

export type ApproveResult =
  | { ok: true }
  | { ok: false; error: string };

/**
 * Approve a proposed fix (live mode only).
 *
 * Propose-don't-apply (security rule #2): approving never touches the cluster —
 * it records an immutable audit entry and (later) opens a PR. The role gate is
 * enforced server-side via `requireRole(..,'approver')`, so a viewer cannot
 * approve even if the button were forced visible client-side.
 */
export async function approveFix(fixId: string, runId: string): Promise<ApproveResult> {
  if (!authEnabled() || !supabaseConfigured()) {
    return { ok: false, error: 'Approvals require a signed-in session.' };
  }

  const session = await auth();
  const userId = session?.user?.id;
  const accountId = session?.user?.activeAccountId;
  if (!userId || !accountId) {
    return { ok: false, error: 'Not signed in.' };
  }

  try {
    await requireRole(userId, accountId, 'approver');
    await recordAudit({
      accountId,
      actor: session.user?.email ?? userId,
      action: 'fix.approved',
      runId,
      detail: { fixId },
    });
    revalidatePath('/fixes');
    return { ok: true };
  } catch (err) {
    if (err instanceof AccessError) {
      return { ok: false, error: 'You need the approver role to approve fixes.' };
    }
    console.error('[fixes] approve failed:', err);
    return { ok: false, error: 'Could not record the approval.' };
  }
}
