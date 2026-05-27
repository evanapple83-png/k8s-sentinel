import Link from 'next/link';
import { ArrowUpRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { RiskRing, rating } from '@/components/risk-ring';
import { Stat, Bar } from '@/components/bits';
import type { Severity } from '@/lib/types';
import { DEMO_FINDINGS, DEMO_PATHS, DEMO_PREV_RUN, DEMO_RUN } from '@/lib/mock';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_TONE: Record<Severity, string> = {
  critical: 'var(--critical)',
  high: 'var(--critical)',
  medium: 'var(--warn)',
  low: 'var(--clear)',
  info: 'var(--muted-foreground)',
};

export default function OverviewPage() {
  const findings = DEMO_FINDINGS;
  const risk = DEMO_RUN.riskScore ?? 0;

  const bySeverity = SEV_ORDER.map((s) => ({
    sev: s,
    count: findings.filter((f) => f.severity === s).length,
  })).filter((x) => x.count > 0);
  const maxSev = Math.max(...bySeverity.map((x) => x.count), 1);

  const bySource = Object.entries(
    findings.reduce<Record<string, number>>((acc, f) => {
      acc[f.source] = (acc[f.source] ?? 0) + 1;
      return acc;
    }, {}),
  ).sort((a, b) => b[1] - a[1]);
  const maxSrc = Math.max(...bySource.map(([, n]) => n), 1);

  const reachable = findings.filter((f) => f.reachable).length;
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const high = findings.filter((f) => f.severity === 'high').length;
  const deltaFindings = DEMO_RUN.findingCount - DEMO_PREV_RUN.findingCount;

  return (
    <div className="mx-auto max-w-6xl space-y-7">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="text-sm text-muted-foreground">
            prod-eu-1 · scanned 27 May 09:14 · engine {DEMO_RUN.engine}
          </p>
        </div>
        <Button>Run scan</Button>
      </header>

      <div className="grid gap-5 lg:grid-cols-[300px_1fr]">
        <Card className="flex flex-col items-center justify-center gap-4 p-8">
          <RiskRing value={risk} />
          <div className="text-center">
            <div className="text-sm font-medium capitalize">{rating(risk)} risk</div>
            <div className="text-xs text-muted-foreground">
              {deltaFindings === 0
                ? 'no change since last scan'
                : `${deltaFindings > 0 ? '+' : ''}${deltaFindings} findings since last scan`}
            </div>
          </div>
        </Card>

        <div className="space-y-5">
          <div className="grid gap-4 sm:grid-cols-3">
            <Stat label="Critical" value={critical} tone="critical" hint="needs action now" />
            <Stat label="High" value={high} tone="warn" />
            <Stat
              label="Reachable"
              value={reachable}
              tone="critical"
              hint={`of ${findings.length} findings`}
            />
          </div>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Findings by severity</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {bySeverity.map(({ sev, count }) => (
                <div key={sev} className="flex items-center gap-3">
                  <span className="w-16 text-xs capitalize text-muted-foreground">{sev}</span>
                  <Bar value={count} max={maxSev} tone={SEV_TONE[sev]} />
                  <span className="w-6 text-right text-xs tabular-nums">{count}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex-row items-center justify-between pb-3">
            <CardTitle className="text-base">Top attack paths</CardTitle>
            <Link
              href="/paths"
              className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
            >
              View all <ArrowUpRight className="size-3" />
            </Link>
          </CardHeader>
          <CardContent className="space-y-3">
            {DEMO_PATHS.map((p) => (
              <div key={p.id} className="rounded-lg border p-3">
                <div className="mb-1 flex items-center justify-between">
                  <span className="font-mono text-[11px] uppercase text-muted-foreground">
                    {p.entryPoint} →
                  </span>
                  <span
                    className="rounded px-1.5 py-0.5 text-[11px] font-semibold text-white"
                    style={{ background: p.score >= 70 ? 'var(--critical)' : 'var(--warn)' }}
                  >
                    risk {p.score}
                  </span>
                </div>
                <p className="line-clamp-2 text-sm text-muted-foreground">{p.narrative}</p>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Findings by scanner</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {bySource.map(([src, n]) => (
              <div key={src} className="flex items-center gap-3">
                <span className="w-24 font-mono text-xs text-muted-foreground">{src}</span>
                <Bar value={n} max={maxSrc} tone="var(--primary)" />
                <span className="w-6 text-right text-xs tabular-nums">{n}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
