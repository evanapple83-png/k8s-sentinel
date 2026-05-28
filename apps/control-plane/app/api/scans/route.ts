import { NextResponse } from 'next/server';
import { z } from 'zod';
import { supabaseConfigured } from '@/lib/supabase/server';
import { FEATURE_PUBKEY_CONNECT } from '@/lib/flags';
import {
  EnrollmentTokenError,
  ingestPubkeyScan,
} from '@/lib/pubkey-connect';

/**
 * POST /api/scans — push a finished v3 scan report.
 *
 * Auth: Bearer enrollment token (NOT a user session). Token must be tied to
 *       the body's clusterId — mismatch → 401.
 * Body: { clusterId: uuid, report: <v3 engine report> }. The report is the
 *       unmodified JSON ARGUS emits (see ArgusReportJson in lib/argus-mapper.ts).
 * 201:  { scanId, createdAt }
 *
 * Side-effects (atomic from the caller's view): insert into `scans`, call the
 * existing ingestSnapshot() so run/finding/attack_path/choke_point/audit
 * populate, emit synthetic `scan_pushed` event, mark enrollment used_at on
 * first scan, flip cluster.status → connected. The Overview screen renders
 * the result immediately on its next refresh.
 *
 * Behind FEATURE_PUBKEY_CONNECT; 404 when off.
 */

const BodySchema = z.object({
  clusterId: z.string().uuid(),
  // We don't validate the report shape here — the mapper + the wire schema do
  // (the wire schema runs as a trust boundary inside ingestPubkeyScan). The
  // route just caps the body so a malicious caller can't flood the DB.
  report: z.record(z.unknown()),
});

// Generous cap — v3 reports for big clusters can run a few hundred KB after
// scanner output; this matches the v3 wire-schema bounds in lib/wire.ts.
const MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MB

export async function POST(req: Request) {
  if (!FEATURE_PUBKEY_CONNECT) return new NextResponse(null, { status: 404 });
  if (!supabaseConfigured()) {
    return NextResponse.json({ error: 'not configured' }, { status: 503 });
  }

  const rawToken = extractBearer(req);
  if (!rawToken) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });

  const text = await req.text();
  if (text.length > MAX_BODY_BYTES) {
    return NextResponse.json({ error: 'body too large' }, { status: 413 });
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

  try {
    const out = await ingestPubkeyScan({
      rawToken,
      clusterId: parsed.data.clusterId,
      report: parsed.data.report,
    });
    return NextResponse.json(out, { status: 201 });
  } catch (err) {
    if (err instanceof EnrollmentTokenError) {
      // Mismatch / expired / unknown token → 401. Validation-style misses
      // (report shape) also surface here as 401 to avoid an oracle on token
      // state vs. body state; the operator log differentiates.
      const msg = err.message;
      if (msg.startsWith('report failed wire validation')) {
        return NextResponse.json({ error: msg }, { status: 422 });
      }
      if (msg === 'report missing or not an object') {
        return NextResponse.json({ error: msg }, { status: 400 });
      }
      return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
    }
    console.error('[api/scans POST] failed:', err);
    return NextResponse.json({ error: 'ingest failed' }, { status: 500 });
  }
}

function extractBearer(req: Request): string | null {
  const h = req.headers.get('authorization') ?? '';
  const m = h.match(/^Bearer\s+(\S+)$/i);
  return m && m[1] ? m[1] : null;
}
