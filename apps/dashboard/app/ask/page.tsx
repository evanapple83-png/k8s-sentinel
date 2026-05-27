'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { useRuns } from '@/lib/run-context';
import type { AskResult } from '@/lib/types';
import { Dot, PageHeader, ResourceLabel } from '@/components/ui';

const SUGGESTIONS = [
  'show everything internet-exposed running as root',
  'critical findings in prod',
  'what can reach a secret',
  'privileged containers',
];

export default function AskPage() {
  const { runId } = useRuns();
  const [q, setQ] = useState('');
  const [res, setRes] = useState<AskResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(query: string) {
    const text = query.trim();
    if (!text) return;
    setQ(text);
    setLoading(true);
    setError(null);
    try {
      setRes(await api.ask(text, runId ?? undefined));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <PageHeader title="Ask" sub="Plain-English questions over the posture graph." />

      <div className="spotlight">
        <span style={{ fontSize: 20, color: 'var(--muted)' }}>⌕</span>
        <input
          autoFocus
          value={q}
          placeholder="show everything internet-exposed running as root"
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && run(q)}
        />
        <button className="btn primary" onClick={() => run(q)} disabled={loading}>
          {loading ? '…' : 'Ask'}
        </button>
      </div>

      <div className="suggest">
        {SUGGESTIONS.map((s) => (
          <button key={s} onClick={() => run(s)}>
            {s}
          </button>
        ))}
      </div>

      {error ? <div className="banner" style={{ marginTop: 18 }}>{error}</div> : null}

      {res ? (
        <div style={{ marginTop: 24 }}>
          <div className="card" style={{ fontSize: 17, fontWeight: 500 }}>
            {res.answer.answer}
          </div>
          {res.answer.parsed?.unmatched ? (
            <p className="muted" style={{ marginTop: 8 }}>
              Couldn’t interpret “{res.answer.parsed.unmatched}” — showing the best match.
            </p>
          ) : null}

          {res.answer.findings.length > 0 ? (
            <div className="card" style={{ marginTop: 16 }}>
              <div className="list">
                {res.answer.findings.slice(0, 20).map((f) => (
                  <div className="fitem" key={f.id}>
                    <span className="score" style={{ textAlign: 'right' }}>
                      {f.exploitScore ?? 0}
                    </span>
                    <Dot sev={f.severity} />
                    <div>
                      <div className="title">{f.title}</div>
                      <div className="meta">
                        <span className="chip">{f.source}</span> <ResourceLabel resource={f.resource} />
                      </div>
                    </div>
                    <div>{f.reachable ? <span className="reach">reachable</span> : null}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
    </>
  );
}
