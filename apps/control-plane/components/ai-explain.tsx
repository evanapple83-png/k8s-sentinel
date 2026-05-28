'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { cn } from '@/lib/utils';

/**
 * AI narration UI primitives — shared across Findings, Paths, Fixes, Ask.
 *
 * Loading model: lazy on user action (button click / expander open). We
 * deliberately do NOT auto-load on view — keeps per-user spend low, lets the
 * user choose what they actually want explained.
 *
 * Client-side de-dupe: per (clusterId, scanId, target) we cache the response
 * in module-scope so toggling an expander shut and back open doesn't re-call.
 * On `clusterId` change the cache stays (different cluster = different keys),
 * which is what we want — flipping between clusters and back keeps history.
 */

interface Citation {
  type: 'finding' | 'path' | 'chokepoint' | 'jewel';
  id: string;
}

export interface ExplainResult {
  explanation: string;
  citations: Citation[];
  citationWarning: boolean;
  model: string;
  usage: {
    inputTokens: number;
    outputTokens: number;
    cacheCreationInputTokens: number;
    cacheReadInputTokens: number;
  };
}

// Module-scope cache, keyed by stable target descriptor.
const explainCache = new Map<string, ExplainResult>();

/**
 * useExplain — POST to /api/ai/<endpoint> on demand, cache the result.
 *
 * @param cacheKey  Stable key per target (e.g. `finding:${runId}:${id}`). The
 *                  callsite is responsible for picking a key that changes on
 *                  scan refresh — usually `${kind}:${runId}:${id}`. (We don't
 *                  know runId here; the spec defers fully-server-side caching
 *                  to phase 6 — this is just an in-session miss-saver.)
 */
export function useExplain<TBody extends Record<string, unknown>>(
  endpoint: 'explain-finding' | 'explain-path' | 'explain-fix',
  cacheKey: string,
  body: TBody | null,
) {
  const [state, setState] = useState<
    | { kind: 'idle' }
    | { kind: 'loading' }
    | { kind: 'ok'; result: ExplainResult }
    | { kind: 'error'; status: number; message: string; retryAfter?: number }
  >({ kind: 'idle' });

  const run = useCallback(async () => {
    if (!body) return;
    const cached = explainCache.get(cacheKey);
    if (cached) {
      setState({ kind: 'ok', result: cached });
      return;
    }
    setState({ kind: 'loading' });
    try {
      const resp = await fetch(`/api/ai/${endpoint}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (resp.status === 429) {
        const j = await resp.json().catch(() => ({}));
        const retryAfter = Number.parseInt(resp.headers.get('retry-after') ?? '60', 10);
        setState({
          kind: 'error',
          status: 429,
          message: (j as { error?: string }).error ?? 'Rate limit reached. Try again shortly.',
          retryAfter: Number.isFinite(retryAfter) ? retryAfter : 60,
        });
        return;
      }
      if (!resp.ok) {
        const j = await resp.json().catch(() => ({}));
        setState({
          kind: 'error',
          status: resp.status,
          message: (j as { error?: string }).error ?? `Request failed (${resp.status}).`,
        });
        return;
      }
      const result = (await resp.json()) as ExplainResult;
      explainCache.set(cacheKey, result);
      setState({ kind: 'ok', result });
    } catch (err) {
      setState({
        kind: 'error',
        status: 0,
        message: err instanceof Error ? err.message : 'Network error',
      });
    }
  }, [body, cacheKey, endpoint]);

  return { state, run };
}

// ---------------------------------------------------------------------------
// Compact button + popover panel (Findings table, Fixes)
// ---------------------------------------------------------------------------

export function ExplainButton({
  onClick,
  loading,
  size = 'sm',
}: {
  onClick: () => void;
  loading: boolean;
  size?: 'sm' | 'md';
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={loading}
      className={cn(
        'inline-flex items-center gap-1 rounded-full border border-primary/40 bg-primary/5 px-2 py-0.5 text-[11px] font-medium text-primary transition-colors',
        'hover:bg-primary/10 disabled:opacity-50 disabled:cursor-not-allowed',
        size === 'md' && 'px-3 py-1 text-xs',
      )}
      aria-label="Explain in plain English with AI"
      title="AI explanation"
    >
      {loading ? (
        <Spinner />
      ) : (
        <svg
          aria-hidden
          className="size-3"
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.6"
        >
          <path d="M8 1.5l1.7 4.2 4.5.3-3.4 3 1 4.4L8 11l-3.8 2.4 1-4.4L1.8 6l4.5-.3L8 1.5z" />
        </svg>
      )}
      {loading ? 'Explaining…' : 'Explain'}
    </button>
  );
}

function Spinner() {
  return (
    <svg className="size-3 animate-spin" viewBox="0 0 16 16" fill="none">
      <circle cx="8" cy="8" r="6" stroke="currentColor" strokeOpacity="0.25" strokeWidth="1.8" />
      <path
        d="M14 8a6 6 0 0 0-6-6"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Result panel — used inside drawers / expanders.
// ---------------------------------------------------------------------------

export function ExplainResultPanel({
  result,
  compact = false,
}: {
  result: ExplainResult;
  compact?: boolean;
}) {
  return (
    <div className={cn('space-y-2 text-sm leading-relaxed', compact && 'text-[13px]')}>
      <div className="whitespace-pre-wrap text-foreground">{result.explanation}</div>
      {result.citations.length ? (
        <div className="flex flex-wrap items-center gap-1 pt-1 text-[11px]">
          <span className="text-muted-foreground">Based on:</span>
          {result.citations.slice(0, 8).map((c) => (
            <CitationChip key={`${c.type}:${c.id}`} citation={c} />
          ))}
        </div>
      ) : null}
      <div className="flex items-center justify-between pt-1 text-[10px] text-muted-foreground/70">
        <span>{result.model}</span>
        <span title={`input ${result.usage.inputTokens} + output ${result.usage.outputTokens} (${result.usage.cacheReadInputTokens} cached)`}>
          {result.usage.cacheReadInputTokens > 0 ? '⚡ cached' : 'fresh'}
        </span>
      </div>
    </div>
  );
}

export function CitationChip({ citation }: { citation: Citation }) {
  const tone =
    citation.type === 'finding'
      ? 'bg-critical/10 text-critical'
      : citation.type === 'jewel'
        ? 'bg-warn/10 text-warn'
        : citation.type === 'path'
          ? 'bg-primary/10 text-primary'
          : 'bg-muted text-muted-foreground';
  return (
    <span
      className={cn('inline-flex items-center rounded font-mono', tone, 'px-1.5 py-0.5 text-[10px]')}
      title={`${citation.type} · ${citation.id}`}
    >
      {citation.id}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Drawer for the Findings table — side-panel sliding in from the right.
// ---------------------------------------------------------------------------

export function ExplainDrawer({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}) {
  // ESC closes; cleanup the listener when the drawer leaves the tree.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <>
      <div
        className="fixed inset-0 z-40 bg-foreground/20 backdrop-blur-sm transition-opacity"
        onClick={onClose}
        aria-hidden
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l bg-background shadow-lg"
      >
        <header className="flex items-start justify-between gap-3 border-b px-5 py-4">
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold">{title}</h2>
            <p className="mt-0.5 text-[11px] text-muted-foreground">
              AI explanation · scoped to the latest scan
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
            aria-label="Close"
          >
            <svg className="size-4" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6">
              <path d="M4 4l8 8M12 4l-8 8" strokeLinecap="round" />
            </svg>
          </button>
        </header>
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------
// Collapsible inline expander — used by ChokePointsPanel ("Why this fix?")
// and Attack Paths ("AI narration").
// ---------------------------------------------------------------------------

export function ExplainExpander({
  label,
  state,
  onToggle,
  children,
}: {
  label: string;
  state: 'idle' | 'loading' | 'ok' | 'error';
  onToggle: () => void;
  children?: React.ReactNode;
}) {
  const expanded = state !== 'idle';
  return (
    <div className="mt-2 rounded-md border bg-background/40">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-center justify-between gap-2 px-3 py-2 text-left text-[12px] font-medium text-primary transition-colors hover:bg-primary/5"
        aria-expanded={expanded}
      >
        <span className="inline-flex items-center gap-1.5">
          <svg className="size-3" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.6">
            <path d="M8 1.5l1.7 4.2 4.5.3-3.4 3 1 4.4L8 11l-3.8 2.4 1-4.4L1.8 6l4.5-.3L8 1.5z" />
          </svg>
          {label}
          {state === 'loading' ? <Spinner /> : null}
        </span>
        <svg
          className={cn('size-3 transition-transform', expanded && 'rotate-180')}
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.6"
        >
          <path d="M4 6l4 4 4-4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      {expanded ? (
        <div className="border-t bg-background/60 px-3 py-3">
          {children}
        </div>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Convenience hook for the inline expander pattern (Paths, Fixes).
// ---------------------------------------------------------------------------

export function useToggleableExplain<TBody extends Record<string, unknown>>(
  endpoint: 'explain-path' | 'explain-fix',
  cacheKey: string,
  body: TBody | null,
) {
  const { state, run } = useExplain(endpoint, cacheKey, body);
  const ranOnce = useRef(false);
  const [shown, setShown] = useState(false);

  const toggle = useCallback(() => {
    setShown((v) => {
      const next = !v;
      if (next && !ranOnce.current) {
        ranOnce.current = true;
        void run();
      }
      return next;
    });
  }, [run]);

  return { state: shown ? state : ({ kind: 'idle' } as const), run, shown, toggle };
}
