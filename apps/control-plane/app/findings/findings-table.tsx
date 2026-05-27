'use client';

import { useMemo, useState } from 'react';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { SeverityBadge } from '@/components/ui/badge';
import { SourceBadge, ReachableBadge } from '@/components/bits';
import { cn } from '@/lib/utils';
import type { Finding, Severity } from '@/lib/types';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function scoreColor(score: number): string {
  return score >= 70 ? 'var(--critical)' : score >= 40 ? 'var(--warn)' : 'var(--clear)';
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [q, setQ] = useState('');
  const [sevs, setSevs] = useState<Set<Severity>>(new Set());
  const [reachableOnly, setReachableOnly] = useState(false);

  const sources = useMemo(
    () => [...new Set(findings.map((f) => f.source))].sort(),
    [findings],
  );
  const [srcs, setSrcs] = useState<Set<string>>(new Set());

  const rows = useMemo(() => {
    return findings.filter((f) => {
      if (sevs.size && !sevs.has(f.severity)) return false;
      if (srcs.size && !srcs.has(f.source)) return false;
      if (reachableOnly && !f.reachable) return false;
      if (q) {
        const hay = `${f.title} ${f.ruleId} ${f.resource.name} ${f.resource.image ?? ''}`.toLowerCase();
        if (!hay.includes(q.toLowerCase())) return false;
      }
      return true;
    }).sort((a, b) => (b.exploitScore ?? 0) - (a.exploitScore ?? 0));
  }, [findings, q, sevs, srcs, reachableOnly]);

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
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <Row key={f.id} f={f} />
              ))}
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-sm text-muted-foreground">
                    No findings match these filters.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function Row({ f }: { f: Finding }) {
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
        <div className="font-mono text-[11px] text-muted-foreground">{f.ruleId}</div>
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
