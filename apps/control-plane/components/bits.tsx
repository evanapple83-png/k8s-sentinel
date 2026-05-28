import type { ReactNode } from 'react';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import type { ChokePoint, SsvcDecision, ThreatIntel } from '@/lib/types';

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

// ---------------------------------------------------------------------------
// ARGUS v3 — KEV / SSVC / intel / choke-points UI bits
// ---------------------------------------------------------------------------

/**
 * Crimson pill for a CVE listed in CISA's Known-Exploited Vulnerabilities
 * catalog. Drawing the eye on these is the whole point of v3 — they're the
 * findings an attacker is statistically MOST likely to weaponize next.
 */
export function KevBadge() {
  return (
    <span className="inline-flex items-center gap-1 rounded bg-critical/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-critical">
      <span className="size-1 rounded-full bg-critical" /> KEV
    </span>
  );
}

/** Darker variant for KEV entries also tagged "Known Ransomware Campaign Use". */
export function RansomwareBadge() {
  return (
    <span className="inline-flex items-center gap-1 rounded bg-critical px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-critical-foreground">
      ransomware
    </span>
  );
}

const SSVC_TONE: Record<SsvcDecision, string> = {
  Act: 'bg-critical/15 text-critical',
  Attend: 'bg-warn/15 text-warn',
  Track: 'bg-muted text-muted-foreground',
  'Track*': 'bg-muted text-muted-foreground/70',
};

/** SSVC decision pill. Colour follows the same critical→muted ramp as severity. */
export function SsvcBadge({ decision }: { decision: SsvcDecision }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide',
        SSVC_TONE[decision],
      )}
      title={ssvcTooltip(decision)}
    >
      {decision}
    </span>
  );
}

function ssvcTooltip(d: SsvcDecision): string {
  switch (d) {
    case 'Act':    return 'Act — exploited and reaches a crown jewel today';
    case 'Attend': return 'Attend — exploited but not yet reachable';
    case 'Track':  return 'Track — observable; no proven exploit yet';
    case 'Track*': return 'Track* — no exploit, no reachability';
  }
}

/** EPSS percentile chip (probability of exploit in the next 30 days). */
export function EpssChip({ epss }: { epss: number }) {
  const pct = Math.round(epss * 100);
  const tone = pct >= 50 ? 'text-critical' : pct >= 10 ? 'text-warn' : 'text-muted-foreground';
  return (
    <span
      className={cn('font-mono text-[10px] tabular-nums', tone)}
      title={`EPSS — ${pct}% chance of being exploited in the next 30 days`}
    >
      EPSS {pct}%
    </span>
  );
}

/**
 * One-line banner at the top of every dashboard screen, summarising the
 * threat-intel catalog the engine pinned at scan time. Drives the "this run
 * was scored against catalog vN" guarantee — two reruns can't disagree on
 * the same finding's KEV status.
 */
export function IntelBanner({ intel }: { intel: ThreatIntel | null | undefined }) {
  if (!intel) return null;
  const sourceLabel =
    intel.source.startsWith('live:')
      ? `live ${intel.source.slice(5)}`
      : intel.source;
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border border-dashed bg-muted/30 px-3 py-1.5 text-xs text-muted-foreground">
      <span className="font-medium text-foreground">Threat intel</span>
      <span>·</span>
      <span className="font-mono">{sourceLabel}</span>
      <span>·</span>
      <span>catalog {intel.version}</span>
      <span>·</span>
      <span className="tabular-nums">{intel.kevCount.toLocaleString()} KEV entries</span>
      {typeof intel.epssCount === 'number' ? (
        <>
          <span>·</span>
          <span className="tabular-nums">{intel.epssCount.toLocaleString()} EPSS</span>
        </>
      ) : null}
    </div>
  );
}

/**
 * "Apply first" panel — ARGUS choke-points ranked by paths-broken. One control
 * collapsing N attack paths is the headline insight of the v3 engine; the UI
 * has to surface it before any per-finding triage so operators don't drown in
 * the 100s of underlying findings.
 */
export function ChokePointsPanel({
  chokePoints,
  aiSlot,
}: {
  chokePoints: ChokePoint[];
  /**
   * Optional render-prop slotted under each choke-point. Used by the Overview
   * page to mount the "Why this fix?" AI expander as a client island while
   * keeping the panel itself server-rendered.
   */
  aiSlot?: (cp: ChokePoint, index: number) => ReactNode;
}) {
  if (!chokePoints.length) return null;
  return (
    <Card>
      <CardContent className="p-5">
        <div className="mb-3 flex items-baseline justify-between">
          <h2 className="text-base font-semibold">Apply first</h2>
          <span className="text-xs text-muted-foreground">
            {chokePoints.length} choke-point{chokePoints.length === 1 ? '' : 's'} · ranked by paths
            broken
          </span>
        </div>
        <ol className="space-y-2">
          {chokePoints.map((cp, i) => (
            <li key={cp.id} className="rounded-lg border bg-card p-3">
              <div className="flex items-start gap-3">
                <span
                  className="mt-0.5 inline-flex h-7 w-12 shrink-0 items-center justify-center rounded-md text-xs font-bold tabular-nums text-white"
                  style={{
                    background:
                      cp.severity === 'critical'
                        ? 'var(--critical)'
                        : cp.severity === 'high'
                          ? 'var(--critical)'
                          : 'var(--warn)',
                  }}
                  title={`${cp.breaks} of ${cp.totalPaths || '?'} active attack paths`}
                >
                  ×{cp.breaks}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-medium leading-snug">
                    {i + 1}. {cp.description}
                  </div>
                  {cp.targets.length ? (
                    <div className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
                      eliminates → {cp.targets.slice(0, 4).join(' · ')}
                      {cp.targets.length > 4 ? ` +${cp.targets.length - 4} more` : ''}
                    </div>
                  ) : null}
                </div>
              </div>
              {aiSlot ? aiSlot(cp, i) : null}
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}
