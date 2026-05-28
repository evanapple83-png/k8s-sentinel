import { NextResponse } from 'next/server';
import { z } from 'zod';
import { supabaseConfigured } from '@/lib/supabase/server';
import { FEATURE_PUBKEY_CONNECT } from '@/lib/flags';
import {
  EnrollmentTokenError,
  recordConnectionEvent,
  type ConnectionEventType,
} from '@/lib/pubkey-connect';

/**
 * POST /api/clusters/:id/events — append a progress event to the timeline.
 *
 * Auth: Bearer enrollment token (NOT a user session). The token must be tied
 *       to the path's :id. Per contract §4, single-use is enforced: after
 *       used_at is set, only `scan_pushed` is allowed (the CLI may re-post
 *       the same scan_pushed idempotently). All other types after consumption
 *       → 401.
 * Body: { type: EventType, detail?: object } — `detail` is JSON-capped at 2 KB.
 *
 * Behind FEATURE_PUBKEY_CONNECT; 404 when off so the route is unreachable.
 */

const BodySchema = z.object({
  type: z.enum([
    'agent_registered',
    'cli_started',
    'csr_submitted',
    'awaiting_approval',
    'approved',
    'rbac_bound',
    'scan_pushed',
    'error',
  ]),
  detail: z.record(z.unknown()).optional(),
});

const MAX_BODY_BYTES = 2048;

export async function POST(
  req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  if (!FEATURE_PUBKEY_CONNECT) return new NextResponse(null, { status: 404 });
  if (!supabaseConfigured()) {
    return NextResponse.json({ error: 'not configured' }, { status: 503 });
  }

  const rawToken = extractBearer(req);
  if (!rawToken) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });

  // Bound the body to 2 KB BEFORE parsing — defense against an oversized
  // detail blob, per contract §2.
  const text = await req.text();
  if (text.length > MAX_BODY_BYTES) {
    return NextResponse.json({ error: 'body too large (>2 KB)' }, { status: 413 });
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  const parsed = BodySchema.safeParse(json);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'invalid body', issues: parsed.error.issues.slice(0, 3) },
      { status: 400 },
    );
  }

  const { id } = await ctx.params;
  if (!id || typeof id !== 'string') {
    return NextResponse.json({ error: 'invalid id' }, { status: 400 });
  }

  try {
    const out = await recordConnectionEvent({
      rawToken,
      type: parsed.data.type as ConnectionEventType,
      detail: parsed.data.detail ?? {},
    });
    if (out.clusterId !== id) {
      // The token is valid but for a different cluster — 401, don't leak.
      return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
    }
    // Contract: 204 No Content on success.
    return new NextResponse(null, { status: 204 });
  } catch (err) {
    if (err instanceof EnrollmentTokenError) {
      // All token-side problems collapse to 401; the message is the
      // operator-facing reason but doesn't distinguish causes to the caller.
      return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
    }
    console.error('[api/clusters/:id/events POST] failed:', err);
    return NextResponse.json({ error: 'append failed' }, { status: 500 });
  }
}

function extractBearer(req: Request): string | null {
  const h = req.headers.get('authorization') ?? '';
  const m = h.match(/^Bearer\s+(\S+)$/i);
  return m ? m[1] : null;
}
