import { NextResponse } from 'next/server';
import { z } from 'zod';
import { auth } from '@/auth';
import { supabaseConfigured } from '@/lib/supabase/server';
import { FEATURE_AI_NARRATION } from '@/lib/flags';
import { AccessError, requireMembership } from '@/lib/data';
import {
  AiNarrationError,
  CostCapError,
  RateLimitError,
  explainFinding,
} from '@/lib/ai-narration';

/**
 * POST /api/ai/explain-finding
 *
 * Auth: signed-in user session + membership in the active workspace.
 * Body: { clusterId: uuid, findingId: string, accountId: uuid }.
 *       (accountId comes from the dashboard's active-account picker; the
 *       membership guard rejects if the user isn't a member.)
 * 200:  { explanation: string, citations: [{type, id}], citationWarning,
 *         model, usage: {inputTokens, outputTokens, cacheCreationInputTokens,
 *         cacheReadInputTokens} }
 *
 * Behaviour: lib/ai-narration.explainFinding() runs the whole pipeline —
 * pre-flight rate + cost cap, load latest scan, build cached prompt, call
 * Claude, post-check citations, record usage + audit. This handler is purely
 * about HTTP shaping.
 *
 * Behind FEATURE_AI_NARRATION; 404 when off.
 */

const BodySchema = z.object({
  accountId: z.string().uuid(),
  clusterId: z.string().uuid(),
  // Engine-emitted finding IDs are short ascii (e.g. trivy-001, falco:1a2b).
  findingId: z.string().min(1).max(256),
});

export async function POST(req: Request) {
  if (!FEATURE_AI_NARRATION) {
    return new NextResponse(null, { status: 404 });
  }
  if (!supabaseConfigured()) {
    return NextResponse.json({ error: 'not configured' }, { status: 503 });
  }

  // 1. User session.
  const session = await auth();
  const userId = session?.user?.id;
  if (!userId) {
    return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  }

  // 2. Body validation.
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
  const { accountId, clusterId, findingId } = parsed.data;

  // 3. Tenant scope. Throws AccessError on miss → 403.
  try {
    await requireMembership(userId, accountId);
  } catch (err) {
    if (err instanceof AccessError) {
      return NextResponse.json({ error: 'forbidden' }, { status: 403 });
    }
    throw err;
  }

  // 4. The pipeline.
  try {
    const result = await explainFinding({ accountId, userId, clusterId, findingId });
    return NextResponse.json(result, { status: 200 });
  } catch (err) {
    if (err instanceof RateLimitError) {
      return NextResponse.json(
        { error: err.message, retryAfterSeconds: err.retryAfterSeconds },
        { status: 429, headers: { 'retry-after': String(err.retryAfterSeconds) } },
      );
    }
    if (err instanceof CostCapError) {
      return NextResponse.json({ error: err.message, costCap: true }, { status: 429 });
    }
    if (err instanceof AiNarrationError) {
      return NextResponse.json({ error: err.message }, { status: err.status });
    }
    console.error('[/api/ai/explain-finding] unexpected:', err);
    return NextResponse.json({ error: 'internal error' }, { status: 500 });
  }
}
