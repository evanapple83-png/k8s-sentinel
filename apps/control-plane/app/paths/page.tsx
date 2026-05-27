import { Globe, Box, Bug, KeyRound, ShieldAlert, Network } from 'lucide-react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { EmptyState } from '@/components/placeholder';
import type { AttackStep } from '@/lib/types';
import { getActiveData, type SearchParamsInput } from '@/lib/active';

const KIND_META: Record<string, { icon: typeof Box; label: string; tone: string }> = {
  exposed: { icon: Globe, label: 'Exposed', tone: 'var(--critical)' },
  running: { icon: Box, label: 'Running', tone: 'var(--primary)' },
  vulnerable: { icon: Bug, label: 'Vulnerable', tone: 'var(--critical)' },
  'over-privileged': { icon: ShieldAlert, label: 'Over-privileged', tone: 'var(--warn)' },
  'secret-access': { icon: KeyRound, label: 'Secret access', tone: 'var(--critical)' },
};

export default async function PathsPage({
  searchParams,
}: {
  searchParams?: SearchParamsInput;
}) {
  const data = await getActiveData(searchParams);
  const paths = data.snapshot?.paths ?? [];

  if (!data.snapshot || paths.length === 0) {
    return (
      <EmptyState
        title="Attack Paths"
        description="Findings correlated into ranked chains: exposed → running → vulnerable → over-privileged → secret access."
        message="No attack paths yet for this cluster."
      />
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Attack Paths</h1>
        <p className="text-sm text-muted-foreground">
          Findings correlated into ranked chains: exposed → running → vulnerable → over-privileged →
          secret access.
        </p>
      </header>

      {paths.map((p) => (
        <Card key={p.id}>
          <CardHeader className="gap-2">
            <div className="flex items-center justify-between">
              <span className="inline-flex items-center gap-1.5 font-mono text-xs uppercase text-muted-foreground">
                <Network className="size-3.5" /> {p.entryPoint} entry
              </span>
              <span
                className="rounded-md px-2 py-0.5 text-xs font-semibold text-white"
                style={{ background: p.score >= 70 ? 'var(--critical)' : 'var(--warn)' }}
              >
                risk {p.score}/100
              </span>
            </div>
            <p className="text-sm text-muted-foreground">{p.narrative}</p>
          </CardHeader>
          <CardContent>
            <ol className="relative ml-3 border-l pl-6">
              {p.steps.map((s, i) => (
                <StepNode key={i} step={s} last={i === p.steps.length - 1} />
              ))}
            </ol>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function StepNode({ step, last }: { step: AttackStep; last: boolean }) {
  const meta = KIND_META[step.kind] ?? { icon: Box, label: step.kind, tone: 'var(--primary)' };
  const Icon = meta.icon;
  return (
    <li className={last ? '' : 'pb-5'}>
      <span
        className="absolute -left-[13px] grid size-6 place-items-center rounded-full text-white ring-4 ring-card"
        style={{ background: meta.tone }}
      >
        <Icon className="size-3.5" />
      </span>
      <div className="flex flex-wrap items-baseline gap-x-2">
        <span className="text-xs font-semibold uppercase tracking-wide" style={{ color: meta.tone }}>
          {meta.label}
        </span>
        <span className="font-mono text-sm">
          {step.resource.namespace ? `${step.resource.namespace}/` : ''}
          {step.resource.name}
        </span>
        <span className="text-[11px] text-muted-foreground">{step.resource.kind}</span>
      </div>
      <p className="mt-0.5 text-sm text-muted-foreground">{step.detail}</p>
    </li>
  );
}
