'use client';

import { useState } from 'react';
import { Search, Sparkles } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { SeverityBadge } from '@/components/ui/badge';
import { SourceBadge, ReachableBadge } from '@/components/bits';
import type { Finding } from '@/lib/types';

const EXAMPLES = [
  'show everything internet-exposed running as root',
  'which workloads can read secrets',
  'critical reachable findings',
  'what is exposed to the internet',
];

/** Tiny offline matcher — stands in for the real NL query engine on the agent. */
function answer(query: string, all: Finding[]): { text: string; findings: Finding[] } {
  const q = query.toLowerCase();
  const want = (...kw: string[]) => kw.some((k) => q.includes(k));

  let matched = all;
  const filters: string[] = [];

  if (want('root', 'privileg')) {
    matched = matched.filter((f) => /privileg|root/i.test(f.title + f.description));
    filters.push('running privileged / as root');
  }
  if (want('internet', 'exposed', 'expose')) {
    matched = matched.filter((f) => /expos|internet/i.test(f.title + f.description) || f.reachable);
    filters.push('internet-exposed / reachable');
  }
  if (want('secret')) {
    matched = matched.filter((f) => /secret|rbac|role/i.test(f.title + f.description));
    filters.push('secret access');
  }
  if (want('critical')) {
    matched = matched.filter((f) => f.severity === 'critical');
    filters.push('critical');
  }
  if (want('reachable')) {
    matched = matched.filter((f) => f.reachable);
    filters.push('reachable');
  }

  matched = [...matched].sort((a, b) => (b.exploitScore ?? 0) - (a.exploitScore ?? 0)).slice(0, 6);

  const text = filters.length
    ? `${matched.length} finding${matched.length === 1 ? '' : 's'} match ${filters.join(' + ')}, ranked by reachability-weighted exploitability.`
    : `Here are the highest-exploitability findings. Try filtering by "root", "internet", "secret", or "critical".`;

  return { text, findings: matched };
}

export function AskClient({ findings }: { findings: Finding[] }) {
  const [q, setQ] = useState('');
  const [result, setResult] = useState<ReturnType<typeof answer> | null>(null);

  function run(query: string) {
    setQ(query);
    setResult(answer(query, findings));
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header className="text-center">
        <h1 className="text-2xl font-semibold tracking-tight">Ask</h1>
        <p className="text-sm text-muted-foreground">
          Plain-English questions over your posture graph.
        </p>
      </header>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          run(q);
        }}
        className="relative"
      >
        <Search className="pointer-events-none absolute left-4 top-1/2 size-5 -translate-y-1/2 text-muted-foreground" />
        <input
          autoFocus
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Ask about your cluster…"
          className="h-14 w-full rounded-2xl border bg-card pl-12 pr-4 text-base shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        />
      </form>

      {!result ? (
        <div className="flex flex-wrap justify-center gap-2">
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              onClick={() => run(ex)}
              className="rounded-full border px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            >
              {ex}
            </button>
          ))}
        </div>
      ) : (
        <div className="space-y-4">
          <Card>
            <CardContent className="flex gap-3 p-4">
              <Sparkles className="mt-0.5 size-5 shrink-0 text-primary" />
              <p className="text-sm leading-relaxed">{result.text}</p>
            </CardContent>
          </Card>

          <div className="space-y-2">
            {result.findings.map((f) => (
              <Card key={f.id}>
                <CardContent className="flex items-center gap-3 p-3">
                  <span
                    className="inline-flex h-7 w-9 shrink-0 items-center justify-center rounded-md text-xs font-semibold text-white"
                    style={{
                      background:
                        (f.exploitScore ?? 0) >= 70
                          ? 'var(--critical)'
                          : (f.exploitScore ?? 0) >= 40
                            ? 'var(--warn)'
                            : 'var(--clear)',
                    }}
                  >
                    {f.exploitScore ?? 0}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{f.title}</div>
                    <div className="truncate text-[11px] text-muted-foreground">
                      {f.resource.image ?? `${f.resource.kind} ${f.resource.name}`}
                    </div>
                  </div>
                  <SeverityBadge severity={f.severity} />
                  <SourceBadge source={f.source} />
                  <ReachableBadge reachable={f.reachable} />
                </CardContent>
              </Card>
            ))}
            {result.findings.length === 0 ? (
              <p className="text-center text-sm text-muted-foreground">
                No findings match that question.
              </p>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
}
