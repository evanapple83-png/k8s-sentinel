'use client';

import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { triggerScan } from './connect/actions';

/**
 * Overview "Run scan" button. Dispatches a scan to the active cluster via the
 * relay command bridge (same server action the Connect screen uses). Approver+
 * only; results stream back over the ingest webhook and the page reflects them
 * on next load. In demo mode (no clusterId) the button is disabled.
 */
export function RunScanButton({ clusterId }: { clusterId: string | null }) {
  const [state, setState] = useState<'idle' | 'running' | 'done' | string>('idle');

  async function run() {
    if (!clusterId) return;
    setState('running');
    const res = await triggerScan(clusterId);
    if (res.ok) {
      setState('done');
      setTimeout(() => setState('idle'), 5000);
    } else {
      setState(`couldn’t start a scan (${res.reason})`);
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <Button onClick={run} disabled={!clusterId || state === 'running'}>
        {state === 'running' ? (
          <>
            <Loader2 className="size-4 animate-spin" /> Scanning…
          </>
        ) : (
          'Run scan'
        )}
      </Button>
      {state !== 'idle' && state !== 'running' && (
        <span className="text-xs text-muted-foreground">
          {state === 'done' ? 'Scan started — results appear shortly.' : state}
        </span>
      )}
    </div>
  );
}
