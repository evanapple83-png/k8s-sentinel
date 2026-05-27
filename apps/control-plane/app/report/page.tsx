import { FileText, FileJson, FileType } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { buttonVariants } from '@/components/ui/button';
import { SeverityBadge } from '@/components/ui/badge';
import { EmptyState } from '@/components/placeholder';
import { cn } from '@/lib/utils';
import type { Severity } from '@/lib/types';
import { getActiveData, type SearchParamsInput } from '@/lib/active';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const fmt = (iso: string) =>
  new Date(iso).toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'UTC',
  });

export default async function ReportPage({
  searchParams,
}: {
  searchParams?: SearchParamsInput;
}) {
  const data = await getActiveData(searchParams);

  if (!data.snapshot) {
    return (
      <EmptyState
        title="Report"
        description="Audit-ready summary for your active cluster."
      />
    );
  }

  const { run, findings, paths } = data.snapshot;
  const clusterName =
    data.clusters.find((c) => c.id === run.clusterId)?.name ?? 'cluster';
  const topPath = paths[0];

  const frameworks = [...new Set(findings.flatMap((f) => f.controls?.map((c) => c.framework) ?? []))];
  const counts = SEV_ORDER.map((s) => ({ s, n: findings.filter((f) => f.severity === s).length }));

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Report</h1>
          <p className="text-sm text-muted-foreground">Audit-ready summary for {clusterName}.</p>
        </div>
        <div className="flex gap-2">
          <span className={cn(buttonVariants({ variant: 'outline', size: 'sm' }))}>
            <FileText className="size-4" /> PDF
          </span>
          <span className={cn(buttonVariants({ variant: 'outline', size: 'sm' }))}>
            <FileType className="size-4" /> Markdown
          </span>
          <span className={cn(buttonVariants({ variant: 'outline', size: 'sm' }))}>
            <FileJson className="size-4" /> JSON
          </span>
        </div>
      </header>

      <Card>
        <CardContent className="space-y-6 p-8">
          <div>
            <div className="text-xs uppercase tracking-wide text-muted-foreground">
              Security posture report
            </div>
            <h2 className="text-xl font-semibold">
              {clusterName} — risk {run.riskScore ?? 0}/100
            </h2>
            <div className="text-sm text-muted-foreground">
              {run.findingCount} findings · {run.pathCount} attack paths · engine {run.engine} ·{' '}
              {fmt(run.createdAt)} UTC
            </div>
          </div>

          <Section title="Executive summary">
            <p className="text-sm leading-relaxed text-muted-foreground">
              {run.summary ?? 'No summary available for this run.'}
            </p>
          </Section>

          <Section title="Severity breakdown">
            <div className="flex flex-wrap gap-2">
              {counts
                .filter((c) => c.n > 0)
                .map((c) => (
                  <span key={c.s} className="inline-flex items-center gap-2">
                    <SeverityBadge severity={c.s} />
                    <span className="text-sm tabular-nums">{c.n}</span>
                  </span>
                ))}
            </div>
          </Section>

          {topPath ? (
            <Section title="Highest-priority attack path">
              <div className="rounded-lg border-l-4 border-l-critical bg-muted/40 p-4">
                <div className="mb-1 font-mono text-[11px] uppercase text-muted-foreground">
                  {topPath.entryPoint} → risk {topPath.score}/100
                </div>
                <p className="text-sm leading-relaxed">{topPath.narrative}</p>
              </div>
            </Section>
          ) : null}

          <Section title="Compliance mapping">
            <div className="flex flex-wrap gap-2">
              {frameworks.map((fw) => (
                <span key={fw} className="rounded-md border px-2.5 py-1 font-mono text-xs">
                  {fw}
                </span>
              ))}
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Findings map to {frameworks.length} frameworks. Full control-by-control mapping is
              included in the exported PDF.
            </p>
          </Section>
        </CardContent>
      </Card>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-t pt-5 first:border-t-0 first:pt-0">
      <h3 className="mb-2 text-sm font-semibold">{title}</h3>
      {children}
    </section>
  );
}
