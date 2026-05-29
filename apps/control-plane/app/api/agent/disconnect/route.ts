import { NextResponse } from 'next/server';
import { supabaseConfigured } from '@/lib/supabase/server';
import { markClusterDisconnected } from '@/lib/install-tokens';

/**
 * Agent-disconnect webhook (F1). The relay POSTs here when a registered agent's
 * tunnel drops, so cluster.status flips to `disconnected` and the dashboard /
 * scan trigger never target a dead ("ghost") cluster. Authenticated by the
 * shared RELAY_INGEST_SECRET — no user session. Idempotent + best-effort: a
 * reconnect re-marks the cluster connected via /api/agent/register.
 */
export async function POST(req: Request) {
  const secret = process.env.RELAY_INGEST_SECRET;
  if (!secret || !supabaseConfigured()) {
    return NextResponse.json({ error: 'not configured' }, { status: 503 });
  }
  if (req.headers.get('authorization') !== `Bearer ${secret}`) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  let body: { clusterId?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }
  const clusterId = typeof body.clusterId === 'string' ? body.clusterId : '';
  if (!clusterId) return NextResponse.json({ error: 'missing clusterId' }, { status: 400 });

  try {
    await markClusterDisconnected(clusterId);
    return NextResponse.json({ ok: true }, { status: 200 });
  } catch (err) {
    console.error('[agent/disconnect] failed:', err);
    return NextResponse.json({ error: 'failed' }, { status: 500 });
  }
}
