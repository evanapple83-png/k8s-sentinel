import { NextResponse } from 'next/server';
import { supabaseConfigured } from '@/lib/supabase/server';
import { ingestSnapshot } from '@/lib/data';
import { IngestBodySchema } from '@/lib/wire';

/**
 * Posture ingest webhook (hybrid mode, fase 2). The relay POSTs each push from
 * an in-cluster agent here. Authenticated by the shared RELAY_INGEST_SECRET —
 * there is no user session. The body is re-validated against the wire contract
 * (trust boundary) before it reaches the database. Stores normalized posture
 * only; never secrets, credentials, or raw manifests (docs/DATA-BOUNDARY.md).
 */
export async function POST(req: Request) {
  const secret = process.env.RELAY_INGEST_SECRET;
  if (!secret || !supabaseConfigured()) {
    return NextResponse.json({ error: 'ingest not configured' }, { status: 503 });
  }
  if (req.headers.get('authorization') !== `Bearer ${secret}`) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  let json: unknown;
  try {
    json = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  const parsed = IngestBodySchema.safeParse(json);
  if (!parsed.success) {
    return NextResponse.json(
      { error: 'invalid snapshot', issues: parsed.error.issues.slice(0, 5) },
      { status: 422 },
    );
  }

  try {
    const { runId } = await ingestSnapshot(parsed.data.clusterId, parsed.data.snapshot);
    return NextResponse.json({ ok: true, runId }, { status: 201 });
  } catch (err) {
    // Unknown cluster → 404; anything else → 500 (don't leak internals).
    if (err instanceof Error && err.name === 'AccessError') {
      return NextResponse.json({ error: 'unknown cluster' }, { status: 404 });
    }
    console.error('[agent/ingest] failed:', err);
    return NextResponse.json({ error: 'ingest failed' }, { status: 500 });
  }
}
