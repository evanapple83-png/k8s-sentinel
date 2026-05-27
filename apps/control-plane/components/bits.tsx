import type { ReactNode } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

/** A compact KPI tile for the data-dense dashboard. */
export function Stat({
  label,
  value,
  hint,
  tone = 'default',
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: 'default' | 'critical' | 'warn' | 'clear';
}) {
  const toneCls =
    tone === 'critical'
      ? 'text-critical'
      : tone === 'warn'
        ? 'text-warn'
        : tone === 'clear'
          ? 'text-clear'
          : 'text-foreground';
  return (
    <Card>
      <CardContent className="p-5">
        <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </div>
        <div className={cn('mt-1 text-2xl font-semibold tabular-nums', toneCls)}>{value}</div>
        {hint ? <div className="mt-1 text-xs text-muted-foreground">{hint}</div> : null}
      </CardContent>
    </Card>
  );
}

/** Small monospace pill for a scanner source. */
export function SourceBadge({ source }: { source: string }) {
  return (
    <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
      {source}
    </span>
  );
}

/** Reachable indicator — color + text (never color alone). */
export function ReachableBadge({ reachable }: { reachable?: boolean }) {
  if (reachable) {
    return (
      <span className="inline-flex items-center gap-1 rounded-full bg-critical/10 px-2 py-0.5 text-[11px] font-medium text-critical">
        <span className="size-1.5 rounded-full bg-critical" /> reachable
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
      <span className="size-1.5 rounded-full bg-muted-foreground/50" /> not reachable
    </span>
  );
}

/** Horizontal proportion bar used in breakdowns. */
export function Bar({ value, max, tone }: { value: number; max: number; tone: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: tone }} />
    </div>
  );
}
