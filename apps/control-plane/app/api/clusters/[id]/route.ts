import { NextResponse } from 'next/server';
import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';
import { supabaseConfigured } from '@/lib/supabase/server';
import { FEATURE_PUBKEY_CONNECT } from '@/lib/flags';
import { AccessError } from '@/lib/data';
import { getClusterDetail } from '@/lib/pubkey-connect';

/**
 * GET /api/clusters/:id — return the cluster + event timeline + last scan id.
 *
 * Auth: signed-in session; tenant-scoped via requireMembership inside
 *       getClusterDetail. 404 if the cluster doesn't belong to the active
 *       account (no oracle).
 * Drives the UI status stepper (the page polls this every 3s).
 *
 * Behind FEATURE_PUBKEY_CONNECT; 404 when off.
 */
export async function GET(
  _req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  if (!FEATURE_PUBKEY_CONNECT) return new NextResponse(null, { status: 404 });
  if (!authEnabled() || !supabaseConfigured()) {
    return NextResponse.json({ error: 'not configured' }, { status: 503 });
  }

  const session = await auth();
  const userId = session?.user?.id;
  const accountId = session?.user?.activeAccountId;
  if (!userId || !accountId) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  const { id } = await ctx.params;
  if (!id || typeof id !== 'string') {
    return NextResponse.json({ error: 'invalid id' }, { status: 400 });
  }

  try {
    const detail = await getClusterDetail(userId, accountId, id);
    if (!detail) return NextResponse.json({ error: 'not found' }, { status: 404 });
    return NextResponse.json(detail, { status: 200 });
  } catch (err) {
    if (err instanceof AccessError) {
      return NextResponse.json({ error: 'forbidden' }, { status: 403 });
    }
    console.error('[api/clusters/:id GET] failed:', err);
    return NextResponse.json({ error: 'lookup failed' }, { status: 500 });
  }
}
