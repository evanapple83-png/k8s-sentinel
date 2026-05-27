'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { Check, Copy, Loader2, PlugZap, ShieldAlert } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button, buttonVariants } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { generateInstall, pollConnection } from './actions';

type Phase = 'loading' | 'ready' | 'connected' | 'forbidden' | 'error';

export function ConnectClient() {
  const [phase, setPhase] = useState<Phase>('loading');
  const [command, setCommand] = useState('');
  const [clusterName, setClusterName] = useState('');
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (timer.current) clearInterval(timer.current);
    timer.current = null;
  }, []);

  const generate = useCallback(async () => {
    setPhase('loading');
    const res = await generateInstall();
    if (!res.ok) {
      setPhase(res.reason === 'forbidden' ? 'forbidden' : 'error');
      return;
    }
    setCommand(res.command);
    setPhase('ready');
  }, []);

  useEffect(() => {
    void generate();
  }, [generate]);

  // Poll for the agent registering once a command is shown.
  useEffect(() => {
    if (phase !== 'ready') return;
    timer.current = setInterval(async () => {
      const res = await pollConnection();
      if (res.connected) {
        setClusterName(res.cluster.name);
        setPhase('connected');
        stopPolling();
      }
    }, 3000);
    return stopPolling;
  }, [phase, stopPolling]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  }

  if (phase === 'connected') {
    return (
      <Card>
        <CardContent className="flex flex-col items-center gap-4 p-12 text-center">
          <span className="grid size-12 place-items-center rounded-full bg-clear/15 text-clear">
            <Check className="size-7" />
          </span>
          <div>
            <div className="text-lg font-semibold">Cluster connected ✓</div>
            <p className="text-sm text-muted-foreground">
              <span className="font-mono">{clusterName}</span> registered and the first scan has
              started automatically. Results appear on the Overview shortly.
            </p>
          </div>
          <Link href="/" className={cn(buttonVariants())}>
            Go to Overview
          </Link>
        </CardContent>
      </Card>
    );
  }

  if (phase === 'forbidden') {
    return (
      <Card>
        <CardContent className="flex items-center gap-3 p-6 text-sm text-muted-foreground">
          <ShieldAlert className="size-5 shrink-0 text-warn" />
          Only an <span className="font-medium text-foreground">admin</span> can generate an install
          command. Ask an account admin to connect the cluster.
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardContent className="space-y-4 p-6">
        <ol className="space-y-1 text-sm text-muted-foreground">
          <li>1. Run this in a cluster where you have admin (it installs a read-only agent).</li>
          <li>2. The agent dials out to the relay — no Ingress, no port-forward.</li>
          <li>3. This page flips to “connected” automatically.</li>
        </ol>

        <div className="relative">
          <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-4 pr-12 text-[12px] leading-relaxed">
            <code className="font-mono">{phase === 'loading' ? 'Generating install command…' : command}</code>
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

        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            {phase === 'ready' ? (
              <>
                <Loader2 className="size-3.5 animate-spin" /> Waiting for the agent to register…
              </>
            ) : (
              <>
                <PlugZap className="size-3.5" /> token is single-use and expires in 15 minutes
              </>
            )}
          </span>
          <Button variant="ghost" size="sm" onClick={generate}>
            Regenerate
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
