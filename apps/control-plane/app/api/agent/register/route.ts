import { NextResponse } from 'next/server';
import { consumeInstallToken, TokenError } from '@/lib/install-tokens';

/**
 * Agent registration endpoint (hybrid onboarding). The in-cluster agent POSTs
 * its install token here on first boot; we exchange it for a registered cluster
 * and kick the first scan. Authenticated solely by the (single-use, 15-min)
 * token — there is no user session. In fase 2 the relay issues the agent's mTLS
 * client cert as part of this exchange.
 */
export async function POST(req: Request) {
  let body: { token?: unknown; agentVersion?: unknown; clusterName?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  const token = typeof body.token === 'string' ? body.token : '';
  if (!token) return NextResponse.json({ error: 'missing token' }, { status: 400 });

  try {
    const result = await consumeInstallToken(token, {
      agentVersion: typeof body.agentVersion === 'string' ? body.agentVersion : undefined,
      clusterName: typeof body.clusterName === 'string' ? body.clusterName : undefined,
    });
    return NextResponse.json(
      { clusterId: result.clusterId, runId: result.runId, scan: 'started' },
      { status: 201 },
    );
  } catch (err) {
    if (err instanceof TokenError) {
      // 401: token bad / used / expired — don't leak which.
      return NextResponse.json({ error: 'invalid or expired install token' }, { status: 401 });
    }
    console.error('[agent/register] failed:', err);
    return NextResponse.json({ error: 'registration failed' }, { status: 500 });
  }
}
