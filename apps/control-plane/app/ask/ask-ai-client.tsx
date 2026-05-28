'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { Search, Sparkles } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { CitationChip } from '@/components/ai-explain';

/**
 * AI-powered Ask — streaming chat over /api/ai/ask.
 *
 * UX behaviours per spec §5:
 *   * Show the active scan timestamp at the top ("answering from scan at …")
 *   * Reset conversation on cluster change (page-level: changing `clusterId`
 *     prop drops conversationId + history)
 *   * Show citations inline as F-001 / path badges in the post-stream done
 *     event, rendered as clickable chips that scroll to the matching item
 *     elsewhere in the dashboard
 *
 * Stream protocol matches lib/ai-narration-ask.ts:
 *   data: {"type":"delta","text":"…"}
 *   data: {"type":"done","conversationId","model","citations","usage","citationWarning"}
 *   data: {"type":"error","message"}
 */

interface Citation {
  type: 'finding' | 'path' | 'chokepoint' | 'jewel';
  id: string;
}

type Turn =
  | { role: 'user'; content: string }
  | {
      role: 'assistant';
      content: string;
      citations: Citation[];
      citationWarning: boolean;
      model?: string;
      streaming: boolean;
    };

const EXAMPLES = [
  'Show everything internet-exposed running as root.',
  'Which service accounts can read Secrets cluster-wide?',
  'What changed since the last scan?',
  'Why is the top finding ranked highest?',
];

export function AskAiClient({
  accountId,
  clusterId,
  scannedAt,
}: {
  accountId: string;
  clusterId: string;
  scannedAt: string | null;
}) {
  const [q, setQ] = useState('');
  const [turns, setTurns] = useState<Turn[]>([]);
  const [conversationId, setConversationId] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const conversationIdRef = useRef<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  // Reset on cluster change — different cluster ⇒ different latest scan ⇒
  // any prior turns reference a different dataset, so drop them.
  useEffect(() => {
    setTurns([]);
    setConversationId(null);
    conversationIdRef.current = null;
    setError(null);
    setQ('');
    abortRef.current?.abort();
  }, [clusterId]);

  // Tidy up the in-flight fetch on unmount.
  useEffect(() => () => abortRef.current?.abort(), []);

  const sendQuestion = useCallback(
    async (question: string) => {
      if (!question.trim() || pending) return;
      setError(null);
      setPending(true);
      setQ('');

      // Optimistic: render the user's turn immediately + a streaming assistant
      // placeholder we append text into.
      setTurns((prev) => [
        ...prev,
        { role: 'user', content: question },
        { role: 'assistant', content: '', citations: [], citationWarning: false, streaming: true },
      ]);

      const ctrl = new AbortController();
      abortRef.current?.abort();
      abortRef.current = ctrl;

      try {
        const resp = await fetch('/api/ai/ask', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            accountId,
            clusterId,
            question,
            conversationId: conversationIdRef.current ?? undefined,
          }),
          signal: ctrl.signal,
        });

        if (resp.status === 429) {
          const j = await resp.json().catch(() => ({}));
          const retry = Number.parseInt(resp.headers.get('retry-after') ?? '60', 10);
          throw new Error(
            `${(j as { error?: string }).error ?? 'Rate limit reached.'}${Number.isFinite(retry) ? ` Try again in ~${retry}s.` : ''}`,
          );
        }
        if (!resp.ok || !resp.body) {
          const j = await resp.json().catch(() => ({}));
          throw new Error((j as { error?: string }).error ?? `Request failed (${resp.status}).`);
        }

        await consumeStream(resp.body, {
          onDelta: (text) =>
            setTurns((prev) => {
              const next = [...prev];
              const last = next[next.length - 1];
              if (last && last.role === 'assistant') {
                next[next.length - 1] = { ...last, content: last.content + text };
              }
              return next;
            }),
          onDone: (frame) => {
            conversationIdRef.current = frame.conversationId;
            setConversationId(frame.conversationId);
            setTurns((prev) => {
              const next = [...prev];
              const last = next[next.length - 1];
              if (last && last.role === 'assistant') {
                next[next.length - 1] = {
                  ...last,
                  citations: frame.citations,
                  citationWarning: frame.citationWarning,
                  model: frame.model,
                  streaming: false,
                };
              }
              return next;
            });
          },
          onError: (msg) => {
            throw new Error(msg);
          },
        });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        setError(msg);
        // Roll back the assistant placeholder to a clean error line.
        setTurns((prev) => {
          const next = [...prev];
          const last = next[next.length - 1];
          if (last && last.role === 'assistant' && last.content === '') {
            next.pop();
          } else if (last && last.role === 'assistant') {
            next[next.length - 1] = { ...last, streaming: false };
          }
          return next;
        });
      } finally {
        setPending(false);
      }
    },
    [accountId, clusterId, pending],
  );

  return (
    <div className="mx-auto max-w-3xl space-y-5">
      <header className="text-center">
        <h1 className="text-2xl font-semibold tracking-tight">Ask</h1>
        <p className="text-sm text-muted-foreground">
          Plain-English questions over your latest scan.
        </p>
        {scannedAt ? (
          <p className="mt-1 text-[11px] text-muted-foreground/70">
            Answering from scan at {new Date(scannedAt).toLocaleString()}
          </p>
        ) : null}
      </header>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          void sendQuestion(q);
        }}
        className="relative"
      >
        <Search className="pointer-events-none absolute left-4 top-1/2 size-5 -translate-y-1/2 text-muted-foreground" />
        <input
          autoFocus
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder={pending ? 'Streaming…' : 'Ask about your cluster…'}
          disabled={pending}
          className="h-14 w-full rounded-2xl border bg-card pl-12 pr-4 text-base shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60"
        />
      </form>

      {!turns.length ? (
        <div className="flex flex-wrap justify-center gap-2">
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              onClick={() => void sendQuestion(ex)}
              className="rounded-full border px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            >
              {ex}
            </button>
          ))}
        </div>
      ) : null}

      {turns.length ? (
        <div className="space-y-3">
          {turns.map((t, i) => (t.role === 'user' ? (
            <UserBubble key={i} content={t.content} />
          ) : (
            <AssistantBubble key={i} turn={t} />
          )))}
        </div>
      ) : null}

      {error ? (
        <div className="rounded-md border border-critical/30 bg-critical/5 p-3 text-[13px] text-critical">
          {error}
        </div>
      ) : null}

      {turns.length && conversationId ? (
        <p className="text-center text-[10px] text-muted-foreground/60">
          Conversation {conversationId.slice(0, 8)} · resets on cluster change
        </p>
      ) : null}
    </div>
  );
}

function UserBubble({ content }: { content: string }) {
  return (
    <div className="flex justify-end">
      <div className="max-w-[85%] rounded-2xl rounded-tr-sm bg-primary px-4 py-2.5 text-sm text-primary-foreground">
        {content}
      </div>
    </div>
  );
}

function AssistantBubble({ turn }: { turn: Extract<Turn, { role: 'assistant' }> }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="mb-2 flex items-center gap-2">
          <Sparkles className="size-4 text-primary" />
          <span className="text-[11px] uppercase tracking-wide text-muted-foreground">
            Analyst{turn.streaming ? ' · streaming…' : ''}
          </span>
        </div>
        <div className="whitespace-pre-wrap text-sm leading-relaxed text-foreground">
          {turn.content}
          {turn.streaming ? (
            <span className="ml-1 inline-block size-2 animate-pulse rounded-full bg-primary align-middle" />
          ) : null}
        </div>
        {!turn.streaming && turn.citations.length ? (
          <div className="mt-3 flex flex-wrap items-center gap-1 text-[11px]">
            <span className="text-muted-foreground">Based on:</span>
            {turn.citations.slice(0, 12).map((c) => (
              <CitationChip key={`${c.type}:${c.id}`} citation={c} />
            ))}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// SSE stream consumer — same wire format the route emits.
// ---------------------------------------------------------------------------

interface StreamHandlers {
  onDelta: (text: string) => void;
  onDone: (frame: {
    conversationId: string;
    model: string;
    citations: Citation[];
    citationWarning: boolean;
  }) => void;
  onError: (message: string) => void;
}

async function consumeStream(body: ReadableStream<Uint8Array>, h: StreamHandlers) {
  const reader = body.getReader();
  const dec = new TextDecoder();
  let buffer = '';
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += dec.decode(value, { stream: true });
    let sep: number;
    while ((sep = buffer.indexOf('\n\n')) !== -1) {
      const raw = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      const dataLines = raw.split('\n').filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trim());
      if (!dataLines.length) continue;
      let frame: { type: string; text?: string; message?: string; conversationId?: string; model?: string; citations?: Citation[]; citationWarning?: boolean };
      try {
        frame = JSON.parse(dataLines.join('\n'));
      } catch {
        continue;
      }
      if (frame.type === 'delta' && typeof frame.text === 'string') {
        h.onDelta(frame.text);
      } else if (frame.type === 'done' && frame.conversationId && frame.model) {
        h.onDone({
          conversationId: frame.conversationId,
          model: frame.model,
          citations: frame.citations ?? [],
          citationWarning: Boolean(frame.citationWarning),
        });
        return;
      } else if (frame.type === 'error') {
        h.onError(frame.message ?? 'Stream error');
        return;
      }
    }
  }
}
