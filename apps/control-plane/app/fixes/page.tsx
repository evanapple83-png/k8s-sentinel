'use client';

import { useState } from 'react';
import { Check, GitPullRequest, FilePlus2, FileCode } from 'lucide-react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { SeverityBadge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { Fix } from '@/lib/types';
import { DEMO_FIXES } from '@/lib/mock';

export default function FixesPage() {
  const [approved, setApproved] = useState<Set<string>>(new Set());

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Fixes</h1>
        <p className="text-sm text-muted-foreground">
          Reachability-ranked, reviewable remediations. Approving opens a PR — the agent never
          applies changes in-cluster.
        </p>
      </header>

      {DEMO_FIXES.map((fix) => (
        <FixCard
          key={fix.id}
          fix={fix}
          approved={approved.has(fix.id)}
          onApprove={() => setApproved((s) => new Set(s).add(fix.id))}
        />
      ))}
    </div>
  );
}

function FixCard({ fix, approved, onApprove }: { fix: Fix; approved: boolean; onApprove: () => void }) {
  const KindIcon = fix.kind === 'new-file' ? FilePlus2 : FileCode;
  return (
    <Card>
      <CardHeader className="gap-2 pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="grid size-6 place-items-center rounded-full bg-muted text-xs font-semibold tabular-nums">
              {fix.priority}
            </span>
            <h2 className="font-semibold">{fix.title}</h2>
            <SeverityBadge severity={fix.severity} />
          </div>
          {approved ? (
            <span className="inline-flex items-center gap-1.5 rounded-md bg-clear/15 px-2.5 py-1 text-xs font-medium text-clear">
              <Check className="size-3.5" /> Approved · {fix.branch}
            </span>
          ) : (
            <Button size="sm" onClick={onApprove}>
              <GitPullRequest className="size-4" /> Approve &amp; open PR
            </Button>
          )}
        </div>
        <p className="text-sm text-muted-foreground">{fix.rationale}</p>
        <div className="flex items-center gap-1.5 font-mono text-[11px] text-muted-foreground">
          <KindIcon className="size-3.5" /> {fix.path}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <DiffView diff={fix.diff} />
        {fix.manualSteps.length ? (
          <ul className="space-y-1 text-sm text-muted-foreground">
            {fix.manualSteps.map((s, i) => (
              <li key={i} className="flex gap-2">
                <span className="text-muted-foreground/60">·</span>
                {s}
              </li>
            ))}
          </ul>
        ) : null}
        <div className="flex flex-wrap gap-1.5">
          {fix.controls.map((c) => (
            <span key={c.framework + c.id} className="rounded border px-1.5 py-0.5 font-mono text-[11px]">
              {c.framework} {c.id}
            </span>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-3 text-[12px] leading-relaxed">
      <code className="font-mono">
        {diff.split('\n').map((line, i) => {
          const cls = line.startsWith('+')
            ? 'text-clear'
            : line.startsWith('-')
              ? 'text-critical'
              : line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')
                ? 'text-muted-foreground'
                : 'text-foreground/80';
          return (
            <div key={i} className={cn('whitespace-pre', cls)}>
              {line || ' '}
            </div>
          );
        })}
      </code>
    </pre>
  );
}
