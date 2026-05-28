import 'server-only';
import { createHash, randomUUID } from 'node:crypto';
import { supabaseAdmin } from './supabase/server';
import {
  AiNarrationError,
  RateLimitError,
  CostCapError,
  SYSTEM_PROMPT,
  buildAskContext,
  checkAndReserveRateLimit,
  costMicroCents,
  extractCitations,
  loadLatestScanReport,
  recordUsage,
  stableStringify,
  writeAudit,
  type Citation,
} from './ai-narration';

/**
 * /api/ai/ask — streaming, conversational free-form Q&A scoped to the active
 * cluster's latest scan.
 *
 * Wire shape (server-sent events):
 *   data: {"type":"delta","text":"…"}       # repeated, every text chunk
 *   data: {"type":"done","citations":[…],"conversationId":"…","model":"…",
 *          "usage":{…},"citationWarning":bool}
 *
 * Conversation state lives in Postgres (table `ai_conversation_turn`,
 * migration 0008). Reset on cluster change is enforced client-side by
 * minting a new conversationId. We cap context at 16 prior turns (8 user +
 * 8 assistant) to keep the prompt cacheable and the input-token spend
 * bounded.
 *
 * Caching: same shape as the explain-* endpoints — system prompt + report
 * are combined into the `system` array with a cache_control breakpoint on
 * the report block. The conversation history lives in `messages` and is
 * inherently uncacheable (varies per turn), but it stays small compared to
 * the report (the bulk of input tokens are the cached prefix).
 */

const ASK_TURN_CAP = 16; // 8 user + 8 assistant
const ASK_MAX_TOKENS = 1024;

export interface AskInput {
  accountId: string;
  userId: string;
  clusterId: string;
  question: string;
  /** Pass undefined on the first turn — we mint and return one. */
  conversationId?: string;
  modelOverride?: string;
  /** For tests: alternative fetch. */
  fetchImpl?: typeof fetch;
}

interface AskDoneFrame {
  type: 'done';
  conversationId: string;
  model: string;
  citations: Citation[];
  citationWarning: boolean;
  usage: {
    inputTokens: number;
    outputTokens: number;
    cacheCreationInputTokens: number;
    cacheReadInputTokens: number;
  };
}

interface AskDeltaFrame {
  type: 'delta';
  text: string;
}

interface AskErrorFrame {
  type: 'error';
  message: string;
  retryAfterSeconds?: number;
}

type AskFrame = AskDeltaFrame | AskDoneFrame | AskErrorFrame;

/**
 * Top-level entry. Returns a ReadableStream<Uint8Array> the route handler
 * wraps in a Response with `Content-Type: text/event-stream`.
 *
 * Errors during setup (missing key, rate-limit, no scan) throw before the
 * stream is built — the route maps them to standard JSON 4xx/5xx. Errors
 * AFTER the stream has started become an `event: error` frame inside the
 * stream — the connection closes cleanly so the client knows it ended.
 */
export async function streamAsk(input: AskInput): Promise<{
  stream: ReadableStream<Uint8Array>;
  /** Echoed in the first delta event AND in the final done event. */
  conversationId: string;
}> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new AiNarrationError(503, 'AI narration not configured: missing ANTHROPIC_API_KEY');
  }
  const model = input.modelOverride ?? process.env.AI_NARRATION_MODEL ?? 'claude-sonnet-4-6';

  // Setup-time gates (route maps to 4xx).
  await checkAndReserveRateLimit({ accountId: input.accountId, userId: input.userId, model });
  const latest = await loadLatestScanReport(input.clusterId);
  if (!latest) {
    throw new AiNarrationError(404, 'No scan found for this cluster yet — run one before asking.');
  }
  const { scanId, report } = latest;
  const askContext = buildAskContext(report);
  const reportJson = stableStringify(askContext);

  // Resolve conversation: load prior turns when given, or mint a fresh id.
  const conversationId = input.conversationId ?? randomUUID();
  const history = input.conversationId
    ? await loadConversationHistory(conversationId, ASK_TURN_CAP)
    : [];

  // Validate question — bounded, never empty.
  const question = input.question.trim().slice(0, 4_000);
  if (!question) {
    throw new AiNarrationError(400, 'Question is empty');
  }

  const messages: Array<{ role: 'user' | 'assistant'; content: string }> = [
    ...history,
    { role: 'user', content: question },
  ];

  const promptHash = createHash('sha256')
    .update(SYSTEM_PROMPT)
    .update('\n--\n')
    .update(reportJson)
    .update('\n--\n')
    .update(JSON.stringify(messages))
    .digest('hex');

  // Build the Anthropic streaming request.
  const requestBody = JSON.stringify({
    model,
    max_tokens: ASK_MAX_TOKENS,
    stream: true,
    system: [
      { type: 'text', text: SYSTEM_PROMPT },
      {
        type: 'text',
        text: `Latest scan report (JSON) for cluster ${askContext.cluster ?? input.clusterId}:\n\n${reportJson}`,
        cache_control: { type: 'ephemeral' },
      },
    ],
    messages,
  });

  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  let upstream: Response;
  try {
    upstream = await fetchImpl('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        accept: 'text/event-stream',
      },
      body: requestBody,
    });
  } catch (err) {
    throw new AiNarrationError(502, 'Anthropic API unreachable', err);
  }

  if (upstream.status === 429) {
    const retryAfter = Number.parseInt(upstream.headers.get('retry-after') ?? '60', 10);
    throw new RateLimitError(Number.isFinite(retryAfter) ? retryAfter : 60, 'Anthropic upstream rate limit reached');
  }
  if (upstream.status === 401 || upstream.status === 403) {
    throw new AiNarrationError(503, 'Anthropic API key invalid or lacks model access');
  }
  if (upstream.status === 529) {
    throw new AiNarrationError(503, 'Anthropic API overloaded — retry shortly');
  }
  if (upstream.status >= 400 || !upstream.body) {
    const body = await upstream.text().catch(() => '');
    throw new AiNarrationError(502, `Anthropic API error ${upstream.status}: ${body.slice(0, 400)}`);
  }

  // Transform Anthropic's SSE stream → our SSE stream.
  const stream = transformAnthropicSse({
    upstream: upstream.body,
    onDone: async (assembled, usage, stopReason) => {
      const { citations, warnings } = extractCitations(assembled, report);
      const hasCitationWarning = warnings.length > 0;
      const finalText = hasCitationWarning
        ? `${assembled}\n\n_Note: this response referenced item${warnings.length === 1 ? '' : 's'} not in the current scan (${warnings.slice(0, 3).join(', ')})._`
        : assembled;
      const cost = costMicroCents(model, usage);

      await Promise.all([
        recordUsage({ accountId: input.accountId, userId: input.userId, costMicroCents: cost }).catch((e) =>
          console.error('[ai-ask] recordUsage failed:', e),
        ),
        writeAudit({
          accountId: input.accountId,
          userId: input.userId,
          clusterId: input.clusterId,
          scanId,
          endpoint: 'ask',
          model,
          targetKind: 'ask',
          targetId: conversationId,
          promptHash,
          status: stopReason === 'refusal' ? 'refused' : 'ok',
          usage,
          costMicroCents: cost,
          outputText: finalText,
          hasCitationWarning,
        }).catch((e) => console.error('[ai-ask] writeAudit failed:', e)),
        appendConversationTurns({
          conversationId,
          accountId: input.accountId,
          userId: input.userId,
          clusterId: input.clusterId,
          turns: [
            { role: 'user', content: question },
            { role: 'assistant', content: finalText },
          ],
        }).catch((e) => console.error('[ai-ask] appendConversationTurns failed:', e)),
      ]);

      const done: AskDoneFrame = {
        type: 'done',
        conversationId,
        model,
        citations,
        citationWarning: hasCitationWarning,
        usage,
      };
      return done;
    },
  });

  return { stream, conversationId };
}

// ---------------------------------------------------------------------------
// SSE transform — parse Anthropic event stream → our frames.
// ---------------------------------------------------------------------------

interface SseTransformOptions {
  upstream: ReadableStream<Uint8Array>;
  /** Called once, when upstream closes naturally. Return the `done` frame to enqueue. */
  onDone: (
    assembledText: string,
    usage: AskDoneFrame['usage'],
    stopReason: string | null,
  ) => Promise<AskDoneFrame>;
}

function transformAnthropicSse(opts: SseTransformOptions): ReadableStream<Uint8Array> {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  return new ReadableStream<Uint8Array>({
    async start(controller) {
      const reader = opts.upstream.getReader();
      const usage: AskDoneFrame['usage'] = {
        inputTokens: 0,
        outputTokens: 0,
        cacheCreationInputTokens: 0,
        cacheReadInputTokens: 0,
      };
      let assembled = '';
      let stopReason: string | null = null;
      let buffer = '';

      const enqueueFrame = (frame: AskFrame) => {
        controller.enqueue(enc.encode(`data: ${JSON.stringify(frame)}\n\n`));
      };

      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += dec.decode(value, { stream: true });
          // SSE frames terminated by \n\n.
          let sep: number;
          while ((sep = buffer.indexOf('\n\n')) !== -1) {
            const rawEvent = buffer.slice(0, sep);
            buffer = buffer.slice(sep + 2);
            const dataLines = rawEvent
              .split('\n')
              .filter((l) => l.startsWith('data:'))
              .map((l) => l.slice(5).trim());
            if (!dataLines.length) continue;
            const payload = dataLines.join('\n');
            if (payload === '[DONE]') continue;
            let event: AnthropicStreamEvent;
            try {
              event = JSON.parse(payload) as AnthropicStreamEvent;
            } catch {
              continue;
            }
            // Process event types we care about.
            if (event.type === 'message_start' && event.message?.usage) {
              const u = event.message.usage;
              usage.inputTokens = u.input_tokens ?? 0;
              usage.cacheCreationInputTokens = u.cache_creation_input_tokens ?? 0;
              usage.cacheReadInputTokens = u.cache_read_input_tokens ?? 0;
            } else if (event.type === 'content_block_delta' && event.delta?.type === 'text_delta') {
              const text = event.delta.text ?? '';
              if (text) {
                assembled += text;
                enqueueFrame({ type: 'delta', text });
              }
            } else if (event.type === 'message_delta') {
              if (event.delta?.stop_reason) stopReason = event.delta.stop_reason;
              if (event.usage?.output_tokens != null) usage.outputTokens = event.usage.output_tokens;
            } else if (event.type === 'message_stop') {
              // Wrap-up — onDone fires after the loop completes naturally.
            } else if (event.type === 'error') {
              const msg = event.error?.message ?? 'upstream error';
              enqueueFrame({ type: 'error', message: msg });
              controller.close();
              reader.cancel().catch(() => undefined);
              return;
            }
          }
        }
        const done = await opts.onDone(assembled, usage, stopReason);
        enqueueFrame(done);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        enqueueFrame({ type: 'error', message: msg });
      } finally {
        controller.close();
      }
    },
  });
}

interface AnthropicStreamEvent {
  type: string;
  message?: {
    usage?: {
      input_tokens?: number;
      output_tokens?: number;
      cache_creation_input_tokens?: number;
      cache_read_input_tokens?: number;
    };
  };
  delta?: {
    type?: string;
    text?: string;
    stop_reason?: string;
  };
  usage?: {
    output_tokens?: number;
  };
  error?: {
    message?: string;
  };
}

// ---------------------------------------------------------------------------
// Conversation persistence — DB-backed turns (migration 0008).
// ---------------------------------------------------------------------------

async function loadConversationHistory(
  conversationId: string,
  cap: number,
): Promise<Array<{ role: 'user' | 'assistant'; content: string }>> {
  const db = supabaseAdmin();
  const { data, error } = await db
    .from('ai_conversation_turn')
    .select('role, content, ord')
    .eq('conversation_id', conversationId)
    .order('ord', { ascending: true })
    .limit(cap);
  if (error) {
    console.error('[ai-ask] loadConversationHistory failed:', error);
    return [];
  }
  return (data ?? []).map((r) => ({
    role: (r as { role: string }).role as 'user' | 'assistant',
    content: (r as { content: string }).content,
  }));
}

async function appendConversationTurns(input: {
  conversationId: string;
  accountId: string;
  userId: string;
  clusterId: string;
  turns: Array<{ role: 'user' | 'assistant'; content: string }>;
}): Promise<void> {
  const db = supabaseAdmin();
  // Find the current max ord for this conversation.
  const { data: prior } = await db
    .from('ai_conversation_turn')
    .select('ord')
    .eq('conversation_id', input.conversationId)
    .order('ord', { ascending: false })
    .limit(1)
    .maybeSingle();
  const startOrd = (prior?.ord as number | undefined) ?? -1;
  const rows = input.turns.map((t, i) => ({
    conversation_id: input.conversationId,
    account_id: input.accountId,
    user_id: input.userId,
    cluster_id: input.clusterId,
    ord: startOrd + 1 + i,
    role: t.role,
    // Cap stored content at 16 KB per turn.
    content: t.content.slice(0, 16_000),
  }));
  const { error } = await db.from('ai_conversation_turn').insert(rows);
  if (error) console.error('[ai-ask] insert turns failed:', error);
}

export { AiNarrationError, RateLimitError, CostCapError };
