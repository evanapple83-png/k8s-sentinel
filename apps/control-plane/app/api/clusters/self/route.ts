import { NextResponse } from 'next/server';
import { supabaseConfigured } from '@/lib/supabase/server';
import { FEATURE_PUBKEY_CONNECT } from '@/lib/flags';
import {
  EnrollmentTokenError,
  resolveEnrollmentToken,
} from '@/lib/pubkey-connect';

/**
 * GET /api/clusters/self — resolve the caller's cluster id from a Bearer
 * enrollment token alone.
 *
 * Why this exists: the wire contract (`docs/PUBKEY_CONNECT_CONTRACT.md`)
 * hands the CLI only the raw enrollment token; everything else (events
 * + scans) needs the cluster id in the body or path. Rather than smuggle
 * the id inside the token format (which is frozen at `ent_<base64url(32)>`),
 * the CLI calls this endpoint once at bootstrap time to resolve its own id.
 *
 * Auth: Bearer enrollment token (NOT a user session) — the matching middleware
 *       exemption is in `auth.config.ts`.
 *
 * Path note: the contract calls this `/_self`, but Next.js App Router treats
 * folders starting with `_` as private (unrouted). We use the URL-safe
 * `self` and the CLI mirrors that. The shape and semantics match the
 * contract exactly.
 */

export async function GET(req: Request) {
  if (!FEATURE_PUBKEY_CONNECT) return new NextResponse(null, { status: 404 });
  if (!supabaseConfigured()) {
    return NextResponse.json({ error: 'not configured' }, { status: 503 });
  }

  const rawToken = extractBearer(req);
  if (!rawToken) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  try {
    const verified = await resolveEnrollmentToken(rawToken);
    // Mirror the field names the CLI already accepts (`id` OR `clusterId`).
    return NextResponse.json({
      id: verified.clusterId,
      method: verified.method,
      expiresAt: verified.expiresAt,
    });
  } catch (err) {
    if (err instanceof EnrollmentTokenError) {
      return NextResponse.json({ error: err.message }, { status: 401 });
    }
    // Surface as 500 — invariant: anything other than EnrollmentTokenError is
    // a server-side bug, not user input. Don't leak the message to the wire.
    console.error('[/api/clusters/self] unexpected:', err);
    return NextResponse.json({ error: 'internal error' }, { status: 500 });
  }
}

function extractBearer(req: Request): string | null {
  const h = req.headers.get('authorization') ?? '';
  const m = h.match(/^Bearer\s+(\S+)$/i);
  return m && m[1] ? m[1] : null;
}
