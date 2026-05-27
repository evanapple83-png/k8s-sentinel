'use client';

import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';

/**
 * Triggers a live scan over SSE and streams the orchestrator's progress
 * messages. Calls onDone(runId) when the run completes.
 */
export function ScanButton({ onDone }: { onDone: (runId: string) => void }) {
  const [running, setRunning] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => () => esRef.current?.close(), []);

  function start() {
    if (running) return;
    setRunning(true);
    setMessage('Connecting…');

    const es = new EventSource(api.scanStreamUrl());
    esRef.current = es;
    let finished = false;

    es.addEventListener('progress', (e) => {
      try {
        setMessage(JSON.parse((e as MessageEvent).data).message as string);
      } catch {
        /* ignore malformed frame */
      }
    });
    es.addEventListener('done', (e) => {
      finished = true;
      es.close();
      esRef.current = null;
      setRunning(false);
      setMessage(null);
      try {
        const id = JSON.parse((e as MessageEvent).data).runId as string;
        if (id) onDone(id);
      } catch {
        /* ignore */
      }
    });
    es.addEventListener('error', () => {
      if (finished) return;
      es.close();
      esRef.current = null;
      setRunning(false);
      setMessage('Scan failed — is the API running (`sentinel serve`)?');
    });
  }

  return (
    <div className="row" style={{ gap: 14 }}>
      <button className="btn primary" onClick={start} disabled={running}>
        {running ? 'Scanning…' : 'Run scan'}
      </button>
      {message ? <span className="progress">{message}</span> : null}
    </div>
  );
}
