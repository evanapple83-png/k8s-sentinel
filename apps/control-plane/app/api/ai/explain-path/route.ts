import { NextResponse } from 'next/server';
import { z } from 'zod';
import { auth } from '@/auth';
import { supabaseConfigured } from '@/lib/supabase/server';
import { FEATURE_AI_NARRATION } from '@/lib/flags';
import { AccessError, requireMembership } from '@/lib/data';
import { AiNarrationError, CostCapError, RateLimitError, explainPath } from '@/lib/ai-narration';

/**
 * POST /api/ai/explain-path — defensively narrate one v3 attack path.
 * Body: { accountId, clusterId, pathTarget }. pathTarget is the v3 jewel key
 * (e.g. 'secret:payments/db-credentials' or 'CLUSTER-ADMIN').
 */

const BodySchema = z
  .object({
    accountId: z.string().uuid(),
    clusterId: z.string().uuid(),
    pathTarget: z.string().min(1).max(256).optional(),
    pathIndex: z.number().int().nonnegative().max(2_000).optional(),
  })
  .refine((b) => b.pathTarget != null || b.pathIndex != null, {
    message: 'Either pathTarget or pathIndex is required',
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
  const { accountId, clusterId, pathTarget, pathIndex } = parsed.data;

  try {
    await requireMembership(userId, accountId);
  } catch (err) {
    if (err instanceof AccessError) return NextResponse.json({ error: 'forbidden' }, { status: 403 });
    throw err;
  }

  try {
    const result = await explainPath({ accountId, userId, clusterId, pathTarget, pathIndex });
    return NextResponse.json(result, { status: 200 });
  } catch (err) {
    if (err instanceof RateLimitError) {
      return NextResponse.json(
        { error: err.message, retryAfterSeconds: err.retryAfterSeconds },
        { status: 429, headers: { 'retry-after': String(err.retryAfterSeconds) } },
      );
    }
    if (err instanceof CostCapError) return NextResponse.json({ error: err.message, costCap: true }, { status: 429 });
    if (err instanceof AiNarrationError) return NextResponse.json({ error: err.message }, { status: err.status });
    console.error('[/api/ai/explain-path] unexpected:', err);
    return NextResponse.json({ error: 'internal error' }, { status: 500 });
  }
}
