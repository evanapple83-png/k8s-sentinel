'use client';

import { useEffect, useMemo, useState } from 'react';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { SeverityBadge } from '@/components/ui/badge';
import {
  SourceBadge,
  ReachableBadge,
  KevBadge,
  RansomwareBadge,
  SsvcBadge,
  EpssChip,
} from '@/components/bits';
import {
  ExplainButton,
  ExplainDrawer,
  ExplainResultPanel,
  useExplain,
} from '@/components/ai-explain';
import { cn } from '@/lib/utils';
import type { Finding, Severity, SsvcDecision } from '@/lib/types';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SSVC_TIERS: SsvcDecision[] = ['Act', 'Attend', 'Track', 'Track*'];

function scoreColor(score: number): string {
  return score >= 70 ? 'var(--critical)' : score >= 40 ? 'var(--warn)' : 'var(--clear)';
}

export interface AiContext {
  accountId: string;
  clusterId: string;
  runId: string;
}

export function FindingsTable({
  findings,
  aiContext = null,
}: {
  findings: Finding[];
  aiContext?: AiContext | null;
}) {
  const [q, setQ] = useState('');
  const [sevs, setSevs] = useState<Set<Severity>>(new Set());
  const [reachableOnly, setReachableOnly] = useState(false);
  const [kevOnly, setKevOnly] = useState(false);
  const [ssvcs, setSsvcs] = useState<Set<SsvcDecision>>(new Set());

  const sources = useMemo(
    () => [...new Set(findings.map((f) => f.source))].sort(),
    [findings],
  );
  const hasV3 = useMemo(
    () => findings.some((f) => f.ssvc != null || f.kev != null || f.epss != null),
    [findings],
  );
  const [srcs, setSrcs] = useState<Set<string>>(new Set());
  const [explainFor, setExplainFor] = useState<Finding | null>(null);

  const rows = useMemo(() => {
    return findings.filter((f) => {
      if (sevs.size && !sevs.has(f.severity)) return false;
      if (srcs.size && !srcs.has(f.source)) return false;
      if (ssvcs.size && (f.ssvc == null || !ssvcs.has(f.ssvc))) return false;
      if (reachableOnly && !f.reachable) return false;
      if (kevOnly && !f.kev) return false;
      if (q) {
        const hay = `${f.title} ${f.ruleId} ${f.resource.name} ${f.resource.image ?? ''} ${f.cve ?? ''}`.toLowerCase();
        if (!hay.includes(q.toLowerCase())) return false;
      }
      return true;
    }).sort((a, b) => (b.exploitScore ?? 0) - (a.exploitScore ?? 0));
  }, [findings, q, sevs, srcs, ssvcs, reachableOnly, kevOnly]);

  function toggle<T>(set: Set<T>, v: T, setter: (s: Set<T>) => void) {
    const next = new Set(set);
    next.has(v) ? next.delete(v) : next.add(v);
    setter(next);
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <p className="text-sm text-muted-foreground">
          Ranked by reachability-weighted exploitability — not raw CVSS.
        </p>
      </header>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search title, CVE, resource…"
          className="max-w-xs"
        />
        <div className="flex flex-wrap gap-1.5">
          {SEVERITIES.map((s) => (
            <Chip key={s} active={sevs.has(s)} onClick={() => toggle(sevs, s, setSevs)}>
              {s}
            </Chip>
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {sources.map((s) => (
            <Chip key={s} active={srcs.has(s)} onClick={() => toggle(srcs, s, setSrcs)} mono>
              {s}
            </Chip>
          ))}
        </div>
        <Chip active={reachableOnly} onClick={() => setReachableOnly((v) => !v)}>
          reachable only
        </Chip>
        {hasV3 ? (
          <>
            <Chip active={kevOnly} onClick={() => setKevOnly((v) => !v)}>
              KEV only
            </Chip>
            <div className="flex flex-wrap gap-1.5">
              {SSVC_TIERS.map((s) => (
                <Chip key={s} active={ssvcs.has(s)} onClick={() => toggle(ssvcs, s, setSsvcs)}>
                  {s}
                </Chip>
              ))}
            </div>
          </>
        ) : null}
        <span className="ml-auto text-xs text-muted-foreground tabular-nums">
          {rows.length} of {findings.length}
        </span>
      </div>

      <Card className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/40 text-left text-xs uppercase tracking-wide text-muted-foreground">
                <th className="px-4 py-2.5 font-medium">Score</th>
                <th className="px-4 py-2.5 font-medium">Severity</th>
                <th className="px-4 py-2.5 font-medium">Finding</th>
                <th className="px-4 py-2.5 font-medium">Resource</th>
                <th className="px-4 py-2.5 font-medium">Source</th>
                <th className="px-4 py-2.5 font-medium">Reachable</th>
                {hasV3 ? <th className="px-4 py-2.5 font-medium">Intel</th> : null}
                {aiContext ? <th className="px-4 py-2.5 font-medium" /> : null}
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <Row key={f.id} f={f} showV3={hasV3} onExplain={aiContext ? () => setExplainFor(f) : undefined} />
              ))}
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={(hasV3 ? 7 : 6) + (aiContext ? 1 : 0)} className="px-4 py-10 text-center text-sm text-muted-foreground">
                    No findings match these filters.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Card>

      {aiContext && explainFor ? (
        <FindingExplainDrawer
          finding={explainFor}
          aiContext={aiContext}
          onClose={() => setExplainFor(null)}
        />
      ) : null}
    </div>
  );
}

function FindingExplainDrawer({
  finding,
  aiContext,
  onClose,
}: {
  finding: Finding;
  aiContext: AiContext;
  onClose: () => void;
}) {
  const cacheKey = `finding:${aiContext.runId}:${finding.id}`;
  const body = useMemo(
    () => ({
      accountId: aiContext.accountId,
      clusterId: aiContext.clusterId,
      findingId: finding.id,
    }),
    [aiContext.accountId, aiContext.clusterId, finding.id],
  );
  const { state, run } = useExplain('explain-finding', cacheKey, body);

  // Auto-run on mount — the drawer opening IS the user's "explain this" intent.
  useEffect(() => {
    if (state.kind === 'idle') void run();
    // run/state intentionally omitted: we want exactly one auto-run per mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <ExplainDrawer open onClose={onClose} title={finding.title}>
      <div className="space-y-3">
        <div className="rounded-md border bg-muted/30 p-3 text-[12px]">
          <div className="font-mono text-[11px] text-muted-foreground">{finding.cve ?? finding.ruleId}</div>
          <div className="mt-1 text-foreground">
            {finding.resource.kind}
            {finding.resource.namespace ? ` · ${finding.resource.namespace}` : ''} ·{' '}
            {finding.resource.name}
          </div>
        </div>
        {state.kind === 'loading' ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <span className="inline-block size-3 animate-pulse rounded-full bg-muted-foreground/40" />
            Asking the analyst…
          </div>
        ) : null}
        {state.kind === 'error' ? (
          <div className="rounded-md border border-critical/30 bg-critical/5 p-3 text-[13px] text-critical">
            {state.message}
            {state.status === 429 ? ` Try again in ~${state.retryAfter ?? 60}s.` : null}
          </div>
        ) : null}
        {state.kind === 'ok' ? <ExplainResultPanel result={state.result} /> : null}
      </div>
    </ExplainDrawer>
  );
}

function Row({ f, showV3, onExplain }: { f: Finding; showV3: boolean; onExplain?: () => void }) {
  const score = f.exploitScore ?? 0;
  return (
    <tr className="border-b transition-colors last:border-0 hover:bg-accent/40">
      <td className="px-4 py-3">
        <span
          className="inline-flex h-7 w-9 items-center justify-center rounded-md text-xs font-semibold tabular-nums text-white"
          style={{ background: scoreColor(score) }}
        >
          {score}
        </span>
      </td>
      <td className="px-4 py-3">
        <SeverityBadge severity={f.severity} />
      </td>
      <td className="max-w-md px-4 py-3">
        <div className="font-medium leading-snug">{f.title}</div>
        <div className="font-mono text-[11px] text-muted-foreground">
          {f.cve ?? f.ruleId}
        </div>
      </td>
      <td className="px-4 py-3">
        <div className="text-sm">{f.resource.image ?? f.resource.name}</div>
        <div className="text-[11px] text-muted-foreground">
          {f.resource.kind}
          {f.resource.namespace ? ` · ${f.resource.namespace}` : ''}
        </div>
      </td>
      <td className="px-4 py-3">
        <SourceBadge source={f.source} />
      </td>
      <td className="px-4 py-3">
        <ReachableBadge reachable={f.reachable} />
      </td>
      {showV3 ? (
        <td className="px-4 py-3">
          <div className="flex flex-wrap items-center gap-1.5">
            {f.ssvc ? <SsvcBadge decision={f.ssvc} /> : null}
            {f.kev ? <KevBadge /> : null}
            {f.ransomware ? <RansomwareBadge /> : null}
            {typeof f.epss === 'number' ? <EpssChip epss={f.epss} /> : null}
            {f.exposure ? (
              <span className="font-mono text-[10px] uppercase text-muted-foreground">
                {f.exposure}
              </span>
            ) : null}
            {f.reaches && f.reaches.length ? (
              <span
                className="font-mono text-[10px] text-critical"
                title={`Reaches crown jewels: ${f.reaches.join(', ')}`}
              >
                ⤳ {f.reaches.slice(0, 2).join(',')}
                {f.reaches.length > 2 ? `+${f.reaches.length - 2}` : ''}
              </span>
            ) : null}
          </div>
        </td>
      ) : null}
      {onExplain ? (
        <td className="px-4 py-3">
          <ExplainButton onClick={onExplain} loading={false} />
        </td>
      ) : null}
    </tr>
  );
}

function Chip({
  active,
  onClick,
  children,
  mono,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'rounded-full border px-2.5 py-1 text-xs capitalize transition-colors',
        mono && 'font-mono lowercase',
        active
          ? 'border-primary bg-primary text-primary-foreground'
          : 'text-muted-foreground hover:bg-accent hover:text-foreground',
      )}
    >
      {children}
    </button>
  );
}
