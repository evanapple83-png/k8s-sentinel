import { NextResponse } from 'next/server';
import { z } from 'zod';
import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';
import { supabaseConfigured } from '@/lib/supabase/server';
import { FEATURE_PUBKEY_CONNECT } from '@/lib/flags';
import { AccessError } from '@/lib/data';
import {
  createClusterEnrollment,
  EnrollmentTokenError,
} from '@/lib/pubkey-connect';

/**
 * POST /api/clusters — mint a pending cluster + single-use enrollment token.
 *
 * Auth: signed-in NextAuth session (via the existing user gate; we additionally
 *       verify session/user/account here so a misconfigured route still 401s).
 * Body: { name: string, method: 'helm' | 'pubkey' } per contract §1.
 * 200:  { id, enrollmentToken (RAW, shown once), expiresAt, method, commands }.
 *
 * Behind FEATURE_PUBKEY_CONNECT. When off, returns 404 so the route is
 * indistinguishable from "endpoint not exposed" (no behaviour change for any
 * existing UI). The raw token is in the response body ONLY — never logged.
 */

const BodySchema = z.object({
  name: z.string().trim().min(1).max(120),
  method: z.enum(['helm', 'pubkey']),
});

export async function POST(req: Request) {
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

  let json: unknown;
  try {
    json = await req.json();
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

  try {
    const out = await createClusterEnrollment({
      userId,
      accountId,
      name: parsed.data.name,
      method: parsed.data.method,
    });
    // Contract §1: response carries the raw token EXACTLY ONCE. After this
    // point the only persisted form is sha256(rawToken).
    return NextResponse.json(
      {
        id: out.id,
        enrollmentToken: out.rawToken,
        expiresAt: out.expiresAt,
        method: out.method,
        commands: out.methodCommands,
      },
      { status: 200 },
    );
  } catch (err) {
    if (err instanceof AccessError) {
      return NextResponse.json({ error: 'forbidden' }, { status: 403 });
    }
    if (err instanceof EnrollmentTokenError) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }
    // Never log the request body (would leak the token if a future change
    // ever puts it in the body). The route never sees a token in input.
    console.error('[api/clusters POST] failed:', err);
    return NextResponse.json({ error: 'mint failed' }, { status: 500 });
  }
}
