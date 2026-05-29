import { NextResponse } from 'next/server';
import { consumeInstallToken, verifyReconnectToken, TokenError } from '@/lib/install-tokens';

/**
 * Agent registration endpoint (hybrid onboarding). Two paths, both authenticated
 * solely by an unguessable token — there is no user session:
 *
 *  1. First boot: the agent POSTs its single-use install token; we exchange it
 *     for a registered cluster, mint a durable reconnect token, kick the first
 *     scan, and return both `clusterId` and `reconnectToken`.
 *  2. Reconnect (issue #11): the agent POSTs `{ clusterId, reconnectToken }`; we
 *     validate the durable token (not single-use) and return its `clusterId`.
 *     This lets the agent survive tunnel drops without re-spending the install
 *     token (which was the cause of the perpetual "registration rejected" loop).
 */
export async function POST(req: Request) {
  let body: { token?: unknown; reconnectToken?: unknown; clusterId?: unknown; agentVersion?: unknown; clusterName?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }

  const reconnectToken = typeof body.reconnectToken === 'string' ? body.reconnectToken : '';
  const clusterId = typeof body.clusterId === 'string' ? body.clusterId : '';

  // Reconnect path takes precedence — a durable credential is present.
  if (reconnectToken && clusterId) {
    try {
      const { clusterId: id } = await verifyReconnectToken(clusterId, reconnectToken);
      return NextResponse.json({ clusterId: id, reconnect: true }, { status: 200 });
    } catch (err) {
      if (err instanceof TokenError) {
        return NextResponse.json({ error: 'invalid reconnect credential' }, { status: 401 });
      }
      console.error('[agent/register] reconnect failed:', err);
      return NextResponse.json({ error: 'registration failed' }, { status: 500 });
    }
  }

  const token = typeof body.token === 'string' ? body.token : '';
  if (!token) return NextResponse.json({ error: 'missing token' }, { status: 400 });

  try {
    const result = await consumeInstallToken(token, {
      agentVersion: typeof body.agentVersion === 'string' ? body.agentVersion : undefined,
      clusterName: typeof body.clusterName === 'string' ? body.clusterName : undefined,
    });
    return NextResponse.json(
      { clusterId: result.clusterId, reconnectToken: result.reconnectToken },
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
