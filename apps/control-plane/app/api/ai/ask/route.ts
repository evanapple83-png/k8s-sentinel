import { NextResponse } from 'next/server';
import { z } from 'zod';
import { auth } from '@/auth';
import { supabaseConfigured } from '@/lib/supabase/server';
import { FEATURE_AI_NARRATION } from '@/lib/flags';
import { AccessError, requireMembership } from '@/lib/data';
import { AiNarrationError, CostCapError, RateLimitError } from '@/lib/ai-narration';
import { streamAsk } from '@/lib/ai-narration-ask';

/**
 * POST /api/ai/ask — streaming, conversational Q&A over the active cluster's
 * latest scan.
 *
 * Body:    { accountId, clusterId, question, conversationId? }
 * Stream:  text/event-stream — `data: {type:"delta",text:"…"}` repeated,
 *          terminated by one `data: {type:"done", conversationId, model,
 *          citations, usage, citationWarning}` or `data: {type:"error",
 *          message}`. Client should mint a fresh `conversationId` on cluster
 *          change to reset history.
 *
 * Setup errors (no key, no scan, rate limit) → JSON 4xx/5xx BEFORE the
 * stream is built. In-stream errors (upstream EOF, parser crash) → an
 * `event: error` frame inside the stream, then a clean close. The HTTP
 * status is always 200 once the stream starts.
 */

const BodySchema = z.object({
  accountId: z.string().uuid(),
  clusterId: z.string().uuid(),
  question: z.string().min(1).max(4_000),
  conversationId: z.string().uuid().optional(),
});

export async function POST(req: Request) {
  if (!FEATURE_AI_NARRATION) return new NextResponse(null, { status: 404 });
  if (!supabaseConfigured()) return NextResponse.json({ error: 'not configured' }, { status: 503 });

  const session = await auth();
  const userId = session?.user?.id;
  if (!userId) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });

  let json: unknown;
  try {
    json = await req.json();
  } catch {
    return NextResponse.json({ error: 'invalid JSON body' }, { status: 400 });
  }
  const parsed = BodySchema.safeParse(json);
  if (!parsed.success) {
    return NextResponse.json({ error: 'invalid body', issues: parsed.error.issues.slice(0, 3) }, { status: 400 });
  }
  const { accountId, clusterId, question, conversationId } = parsed.data;

  try {
    await requireMembership(userId, accountId);
  } catch (err) {
    if (err instanceof AccessError) return NextResponse.json({ error: 'forbidden' }, { status: 403 });
    throw err;
  }

  try {
    const { stream, conversationId: cid } = await streamAsk({
      accountId,
      userId,
      clusterId,
      question,
      conversationId,
    });
    return new Response(stream, {
      status: 200,
      headers: {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache, no-transform',
        connection: 'keep-alive',
        // Echo the conversation id in the headers so a non-streaming client
        // (curl, debugging) can still see it before consuming the body.
        'x-conversation-id': cid,
      },
    });
  } catch (err) {
    if (err instanceof RateLimitError) {
      return NextResponse.json(
        { error: err.message, retryAfterSeconds: err.retryAfterSeconds },
        { status: 429, headers: { 'retry-after': String(err.retryAfterSeconds) } },
      );
    }
    if (err instanceof CostCapError) return NextResponse.json({ error: err.message, costCap: true }, { status: 429 });
    if (err instanceof AiNarrationError) return NextResponse.json({ error: err.message }, { status: err.status });
    console.error('[/api/ai/ask] unexpected:', err);
    return NextResponse.json({ error: 'internal error' }, { status: 500 });
  }
}
