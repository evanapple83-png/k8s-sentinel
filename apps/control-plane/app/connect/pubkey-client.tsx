'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Link from 'next/link';
import { Check, Copy, Loader2, ShieldAlert, Terminal } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button, buttonVariants } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { generatePubkeyEnrollment, pollCluster, type PollClusterResult } from './pubkey-actions';

/**
 * Public-key tab of /connect (FEATURE_PUBKEY_CONNECT only).
 *
 * Renders per docs/PUBKEY_CONNECT_SPEC.md §3:
 *   - intro paragraph + 3-step explainer
 *   - copy-paste `argus bootstrap csr --enroll <token> --control-plane <url>`
 *   - a status stepper driven by GET /api/clusters/:id, polled every 3s
 *   - the kubectl approve command surfaces verbatim from the `awaiting_approval`
 *     event detail when it arrives
 *   - Regenerate mints a fresh token (admin-only — fails with `forbidden`)
 *
 * Lifecycle:
 *   - `enrollment` state holds the clusterId + raw token + command. Raw token
 *     is in memory only; it's never persisted client-side and never goes to
 *     any external log.
 *   - The poller starts when we have a clusterId and stops on `connected`
 *     (terminal happy state) OR on `failed`/`expired`. useEffect cleanup runs
 *     on unmount and on tab switch — no leaked timers.
 */

type Phase = 'loading' | 'ready' | 'forbidden' | 'demo' | 'error';

const STEPS = [
  { key: 'cli_started', label: 'Command issued' },
  { key: 'csr_submitted', label: 'CSR submitted' },
  { key: 'awaiting_approval', label: 'Awaiting admin approval' },
  { key: 'approved', label: 'Approved' },
  { key: 'connected', label: 'First scan received' },
] as const;

type StepKey = (typeof STEPS)[number]['key'];

interface Enrollment {
  clusterId: string;
  command: string;
  rawToken: string;
  expiresAt: string;
}

export function PubkeyConnectClient() {
  const [phase, setPhase] = useState<Phase>('loading');
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [detail, setDetail] = useState<PollClusterResult | null>(null);
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (timer.current) clearInterval(timer.current);
    timer.current = null;
  }, []);

  const generate = useCallback(async () => {
    stopPolling();
    setPhase('loading');
    setDetail(null);
    setEnrollment(null);
    const res = await generatePubkeyEnrollment();
    if (!res.ok) {
      switch (res.reason) {
        case 'demo':
          setPhase('demo');
          return;
        case 'forbidden':
          setPhase('forbidden');
          return;
        default:
          setPhase('error');
          return;
      }
    }
    setEnrollment({
      clusterId: res.clusterId,
      command: res.command,
      rawToken: res.rawToken,
      expiresAt: res.expiresAt,
    });
    setPhase('ready');
  }, [stopPolling]);

  useEffect(() => {
    void generate();
  }, [generate]);

  // Poll for status updates while we have an active enrollment that hasn't
  // reached a terminal state. Cleanup runs on unmount + on tab switch.
  useEffect(() => {
    if (phase !== 'ready' || !enrollment) return;
    let cancelled = false;

    const tick = async () => {
      const res = await pollCluster(enrollment.clusterId);
      if (cancelled) return;
      setDetail(res);
      if (res.ok) {
        const s = res.detail.status;
        if (s === 'connected' || s === 'failed' || s === 'expired') {
          stopPolling();
        }
      }
    };

    // Fire once immediately so the stepper updates as soon as the CLI POSTs
    // its first event — don't wait the full 3s.
    void tick();
    timer.current = setInterval(tick, 3000);
    return () => {
      cancelled = true;
      stopPolling();
    };
  }, [phase, enrollment, stopPolling]);

  const reachedSteps = useMemo(() => computeReached(detail), [detail]);
  const approveCommand = useMemo(() => extractApproveCommand(detail), [detail]);

  async function copy() {
    if (!enrollment) return;
    try {
      await navigator.clipboard.writeText(enrollment.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  if (phase === 'demo') {
    return (
      <Card>
        <CardContent className="space-y-3 p-6 text-sm text-muted-foreground">
          Public-key connect needs a signed-in session and a configured Supabase project.
        </CardContent>
      </Card>
    );
  }

  if (phase === 'forbidden') {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 p-6 text-sm text-muted-foreground">
          <ShieldAlert className="size-5 shrink-0 text-warn" />
          Only an <span className="font-medium text-foreground">admin</span> can mint an enrollment
          token.
        </CardContent>
      </Card>
    );
  }

  if (phase === 'error') {
    return (
      <Card>
        <CardContent className="space-y-3 p-6 text-sm text-muted-foreground">
          Something went wrong minting an enrollment.
          <Button variant="ghost" size="sm" onClick={generate}>
            Try again
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent className="space-y-5 p-6">
        <p className="text-sm text-muted-foreground">
          No agent installed. Your cluster signs a short-lived, read-only certificate it explicitly
          approves. The private key never leaves your machine.
        </p>

        <ol className="space-y-1 text-sm text-muted-foreground">
          <li>1. Run this where you have cluster admin — it generates a fresh keypair + CSR locally.</li>
          <li>2. Approve the certificate when prompted (kubectl).</li>
          <li>3. This page flips to “connected” automatically.</li>
        </ol>

        <div className="relative">
          <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-4 pr-12 text-[12px] leading-relaxed">
            <code className="font-mono">
              {phase === 'loading' || !enrollment ? 'Minting enrollment…' : enrollment.command}
            </code>
          </pre>
          <button
            onClick={copy}
            disabled={phase !== 'ready'}
            aria-label="Copy command"
            className="absolute right-2 top-2 flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground disabled:opacity-40"
          >
            {copied ? <Check className="size-4 text-clear" /> : <Copy className="size-4" />}
          </button>
        </div>

        <Stepper reached={reachedSteps} />

        {approveCommand && (
          <ApproveCommand command={approveCommand} />
        )}

        {detail?.ok && detail.detail.status === 'connected' && (
          <ConnectedRow clusterName={detail.detail.name} clusterId={detail.detail.id} />
        )}
        {detail?.ok && detail.detail.status === 'failed' && (
          <p className="text-xs text-warn">
            Bootstrap failed. Check the CLI output and Regenerate to try again.
          </p>
        )}
        {detail?.ok && detail.detail.status === 'expired' && (
          <p className="text-xs text-warn">
            Enrollment token expired (15-min TTL). Regenerate to mint a fresh one.
          </p>
        )}

        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <Terminal className="size-3.5" /> token is single-use and expires in 15 minutes
          </span>
          <Button variant="ghost" size="sm" onClick={generate}>
            Regenerate
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// --- Stepper UI -------------------------------------------------------------

function Stepper({ reached }: { reached: Set<StepKey> }) {
  return (
    <ol className="space-y-2">
      {STEPS.map((s, i) => {
        const done = reached.has(s.key);
        const active = !done && (i === 0 ? true : reached.has(STEPS[i - 1].key));
        return (
          <li key={s.key} className="flex items-center gap-3">
            <span
              className={cn(
                'grid size-6 place-items-center rounded-full border text-[11px] font-medium',
                done
                  ? 'border-clear bg-clear/10 text-clear'
                  : active
                  ? 'border-foreground/30 bg-background text-foreground'
                  : 'border-border bg-muted/40 text-muted-foreground',
              )}
              aria-hidden
            >
              {done ? <Check className="size-3" /> : i + 1}
            </span>
            <span className={cn('text-sm', done ? 'text-foreground' : active ? 'text-foreground' : 'text-muted-foreground')}>
              {s.label}
              {active && !done && (
                <Loader2 className="ml-2 inline size-3.5 animate-spin text-muted-foreground" />
              )}
              {s.key === 'connected' && done && <span className="ml-1">✓</span>}
            </span>
          </li>
        );
      })}
    </ol>
  );
}

function ApproveCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className="rounded-md border border-dashed bg-muted/30 p-3">
      <p className="mb-2 text-xs text-muted-foreground">
        Run this on a shell with cluster admin to approve the CSR:
      </p>
      <div className="relative">
        <pre className="overflow-x-auto rounded bg-background p-2 pr-10 text-[12px]">
          <code className="font-mono">{command}</code>
        </pre>
        <button
          onClick={onCopy}
          aria-label="Copy approve command"
          className="absolute right-1 top-1 flex size-7 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
        >
          {copied ? <Check className="size-3.5 text-clear" /> : <Copy className="size-3.5" />}
        </button>
      </div>
    </div>
  );
}

function ConnectedRow({ clusterName, clusterId }: { clusterName: string; clusterId: string }) {
  return (
    <div className="flex items-center justify-between rounded-md border bg-clear/5 px-3 py-2 text-sm">
      <span>
        <span className="font-medium">{clusterName}</span>
        <span className="ml-2 text-xs text-muted-foreground font-mono">{clusterId.slice(0, 8)}</span>
        <span className="ml-3 text-xs text-clear">connected</span>
      </span>
      <Link href="/" className={cn(buttonVariants({ size: 'sm' }))}>
        Go to Overview
      </Link>
    </div>
  );
}

// --- Helpers ---------------------------------------------------------------

/**
 * Reduce the event timeline into the set of completed stepper labels.
 *
 * Reached rules:
 *   - cli_started        → step 1 done
 *   - csr_submitted      → step 2 done
 *   - awaiting_approval  → step 3 done (only when the event arrived)
 *   - approved OR rbac_bound → step 4 done
 *   - scan_pushed OR cluster.status==='connected' → step 5 done
 *
 * `connected` is sticky in the reducer so once we land it stays.
 */
function computeReached(res: PollClusterResult | null): Set<StepKey> {
  const reached = new Set<StepKey>();
  if (!res || !res.ok) return reached;
  for (const ev of res.detail.events) {
    switch (ev.type) {
      case 'cli_started':
        reached.add('cli_started');
        break;
      case 'csr_submitted':
        reached.add('cli_started');
        reached.add('csr_submitted');
        break;
      case 'awaiting_approval':
        reached.add('cli_started');
        reached.add('csr_submitted');
        reached.add('awaiting_approval');
        break;
      case 'approved':
      case 'rbac_bound':
        reached.add('cli_started');
        reached.add('csr_submitted');
        reached.add('awaiting_approval');
        reached.add('approved');
        break;
      case 'scan_pushed':
        reached.add('cli_started');
        reached.add('csr_submitted');
        reached.add('awaiting_approval');
        reached.add('approved');
        reached.add('connected');
        break;
      default:
        break;
    }
  }
  if (res.detail.status === 'connected') reached.add('connected');
  return reached;
}

/**
 * Pull the kubectl approve command out of the most recent `awaiting_approval`
 * event detail. The contract carries it verbatim so the operator pastes it
 * one-for-one — no string assembly on the UI side.
 */
function extractApproveCommand(res: PollClusterResult | null): string | null {
  if (!res || !res.ok) return null;
  for (let i = res.detail.events.length - 1; i >= 0; i -= 1) {
    const ev = res.detail.events[i];
    if (ev.type === 'awaiting_approval') {
      const cmd = (ev.detail as { approveCommand?: unknown }).approveCommand;
      if (typeof cmd === 'string' && cmd.length > 0 && cmd.length < 1024) return cmd;
      return null;
    }
  }
  return null;
}
