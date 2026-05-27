'use client';

import { useState, useTransition } from 'react';
import { Check, Copy, Lock } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { toggleCapability } from './actions';

type Risk = 'low' | 'medium' | 'high';

export interface CapabilityView {
  key: string;
  label: string;
  description: string;
  risk: Risk;
  scope: 'cluster' | 'integration';
  snippet: string;
  enabled: boolean;
}

const RISK_CLS: Record<Risk, string> = {
  low: 'bg-clear/15 text-clear',
  medium: 'bg-warn/15 text-warn',
  high: 'bg-critical/15 text-critical',
};

export function PermissionsClient({
  capabilities,
  clusterId,
  live,
  canEdit,
}: {
  capabilities: CapabilityView[];
  clusterId: string;
  live: boolean;
  canEdit: boolean;
}) {
  const [state, setState] = useState<Record<string, boolean>>(
    Object.fromEntries(capabilities.map((c) => [c.key, c.enabled])),
  );
  const [, startTransition] = useTransition();
  const [pending, setPending] = useState<string | null>(null);

  // Demo mode is freely toggleable locally; live mode requires admin.
  const editable = !live || canEdit;

  function onToggle(key: string) {
    if (!editable) return;
    const next = !state[key];
    setState((s) => ({ ...s, [key]: next }));
    if (live) {
      setPending(key);
      startTransition(async () => {
        const res = await toggleCapability(clusterId, key, next);
        if (!res.ok) setState((s) => ({ ...s, [key]: !next })); // revert on failure
        setPending(null);
      });
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base">Elevated capabilities</CardTitle>
        <p className="text-sm text-muted-foreground">
          Opt in to more than read-only. Each toggle shows the exact command to apply — nothing is
          changed in your cluster automatically.
        </p>
        {!live ? (
          <p className="text-xs text-muted-foreground">
            Demo mode — toggles preview the command but aren&apos;t saved.
          </p>
        ) : !canEdit ? (
          <p className="inline-flex items-center gap-1.5 text-xs text-warn">
            <Lock className="size-3.5" /> Only admins can change permissions.
          </p>
        ) : null}
      </CardHeader>
      <CardContent className="space-y-3">
        {capabilities.map((c) => {
          const on = state[c.key] ?? false;
          return (
            <div key={c.key} className="rounded-lg border p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{c.label}</span>
                    <span className={cn('rounded-full px-2 py-0.5 text-[11px] font-medium', RISK_CLS[c.risk])}>
                      {c.risk} risk
                    </span>
                    <span className="rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">
                      {c.scope}
                    </span>
                  </div>
                  <p className="mt-1 max-w-xl text-sm text-muted-foreground">{c.description}</p>
                </div>
                <Switch
                  on={on}
                  disabled={!editable || pending === c.key}
                  onClick={() => onToggle(c.key)}
                />
              </div>
              {on ? <Snippet code={c.snippet} /> : null}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function Switch({ on, disabled, onClick }: { on: boolean; disabled?: boolean; onClick: () => void }) {
  return (
    <button
      role="switch"
      aria-checked={on}
      disabled={disabled}
      onClick={onClick}
      className={cn(
        'relative inline-flex h-6 w-10 shrink-0 items-center rounded-full transition-colors disabled:opacity-40',
        on ? 'bg-primary' : 'bg-muted',
      )}
    >
      <span
        className={cn(
          'inline-block size-5 transform rounded-full bg-background shadow transition-transform',
          on ? 'translate-x-[18px]' : 'translate-x-0.5',
        )}
      />
    </button>
  );
}

function Snippet({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }
  return (
    <div className="relative mt-3">
      <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-3 pr-11 text-[12px] leading-relaxed">
        <code className="font-mono">{code}</code>
      </pre>
      <button
        onClick={copy}
        aria-label="Copy command"
        className="absolute right-2 top-2 flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
      >
        {copied ? <Check className="size-4 text-clear" /> : <Copy className="size-4" />}
      </button>
    </div>
  );
}
