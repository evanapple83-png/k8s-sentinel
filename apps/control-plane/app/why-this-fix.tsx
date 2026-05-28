'use client';

import { useMemo } from 'react';
import {
  ExplainExpander,
  ExplainResultPanel,
  useToggleableExplain,
} from '@/components/ai-explain';

/**
 * "Why this fix?" expander for one choke-point on Overview.
 *
 * The choke-point's position in the report (0-based) is the stable identifier
 * — same order the dashboard renders, same order ChokePoint[] is built by the
 * v3 mapper. Lazy-loaded on toggle.
 */
export function WhyThisFix({
  chokePointIndex,
  ai,
}: {
  chokePointIndex: number;
  ai: { accountId: string; clusterId: string; runId: string };
}) {
  const cacheKey = `fix:${ai.runId}:${chokePointIndex}`;
  const body = useMemo(
    () => ({
      accountId: ai.accountId,
      clusterId: ai.clusterId,
      chokePointIndex,
    }),
    [ai.accountId, ai.clusterId, chokePointIndex],
  );
  const { state, toggle } = useToggleableExplain('explain-fix', cacheKey, body);

  return (
    <ExplainExpander
      label="Why this fix?"
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
