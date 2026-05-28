'use client';

import { useMemo } from 'react';
import {
  ExplainExpander,
  ExplainResultPanel,
  useToggleableExplain,
} from '@/components/ai-explain';

/**
 * Per-path AI narration expander — lazy-loaded on toggle so listing 20 paths
 * doesn't fire 20 model calls. Module-scope cache keeps state across opens.
 *
 * Path identity: the wire AttackPath.id is positional (`ap-N`), so we send
 * `pathIndex` (the 0-based render order on this page) to the API; the backend
 * resolves it to the v3 jewel key from the same scan.
 */
export function PathNarration({
  pathIndex,
  pathLabel,
  ai,
}: {
  pathIndex: number;
  pathLabel: string;
  ai: { accountId: string; clusterId: string; runId: string };
}) {
  const cacheKey = `path:${ai.runId}:${pathIndex}`;
  const body = useMemo(
    () => ({
      accountId: ai.accountId,
      clusterId: ai.clusterId,
      pathIndex,
    }),
    [ai.accountId, ai.clusterId, pathIndex],
  );
  const { state, shown, toggle } = useToggleableExplain('explain-path', cacheKey, body);

  return (
    <ExplainExpander
      label={shown ? `AI narration · ${pathLabel}` : 'AI narration'}
      state={
        state.kind === 'loading'
          ? 'loading'
          : state.kind === 'ok'
            ? 'ok'
            : state.kind === 'error'
              ? 'error'
              : 'idle'
      }
      onToggle={toggle}
    >
      {state.kind === 'loading' ? (
        <div className="text-[12px] text-muted-foreground">Asking the analyst…</div>
      ) : null}
      {state.kind === 'error' ? (
        <div className="rounded-md border border-critical/30 bg-critical/5 p-2 text-[12px] text-critical">
          {state.message}
          {state.status === 429 && state.retryAfter ? ` Try again in ~${state.retryAfter}s.` : null}
        </div>
      ) : null}
      {state.kind === 'ok' ? <ExplainResultPanel result={state.result} compact /> : null}
    </ExplainExpander>
  );
}
