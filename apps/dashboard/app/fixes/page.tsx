'use client';

import { useCallback, useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { useRuns } from '@/lib/run-context';
import type { Fix } from '@/lib/types';
import { Empty, PageHeader, SevPill } from '@/components/ui';

function DiffView({ diff }: { diff: string }) {
  return (
    <pre className="diff">
      {diff.split('\n').map((line, i) => {
        const cls =
          line.startsWith('+') && !line.startsWith('+++')
            ? 'add'
            : line.startsWith('-') && !line.startsWith('---')
              ? 'del'
              : '';
        return (
          <div key={i} className={cls}>
            {line || ' '}
          </div>
        );
      })}
    </pre>
  );
}

export default function FixesPage() {
  const { runId } = useRuns();
  const [fixes, setFixes] = useState<Fix[] | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!runId) {
      setFixes(null);
      return;
    }
    setError(null);
    api
      .fixes(runId)
      .then(setFixes)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [runId]);

  useEffect(load, [load]);

  async function approve(id: string) {
    if (!runId) return;
    setBusy(id);
    setError(null);
    try {
      await api.approve(id, runId);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }

  if (runId && !fixes && !error) {
    return (
      <>
        <PageHeader title="Fixes" />
        <div className="card muted">Loading remediations…</div>
      </>
    );
  }

  if (!runId) {
    return (
      <>
        <PageHeader title="Fixes" />
        <Empty>No run selected. Run a scan on the Overview screen.</Empty>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Fixes"
        sub="Reviewable remediations — approve to write a PR bundle. Nothing is applied automatically."
      />

      {error ? <div className="banner">{error}</div> : null}

      <div className="grid" style={{ gap: 14 }}>
        {(fixes ?? []).map((f) => (
          <div className="card" key={f.id}>
            <div className="row between">
              <div className="row" style={{ gap: 10 }}>
                <SevPill sev={f.severity} />
                <strong>{f.title}</strong>
              </div>
              {f.approved ? (
                <span className="pill ok">✓ approved</span>
              ) : (
                <button className="btn primary sm" onClick={() => approve(f.id)} disabled={busy === f.id}>
                  {busy === f.id ? 'Approving…' : 'Approve → PR'}
                </button>
              )}
            </div>

            <p style={{ margin: '10px 0 8px' }}>{f.rationale}</p>

            <div className="row wrap" style={{ gap: 8, fontSize: 13 }}>
              <span className="chip">{f.kind}</span>
              <span className="chip">{f.path}</span>
              <span className="muted">fixes {f.findingIds.length} finding(s)</span>
              {f.controls.slice(0, 4).map((c) => (
                <span key={c.id} className="chip">
                  {c.id}
                </span>
              ))}
            </div>

            {f.approved ? (
              <div className="muted" style={{ marginTop: 8, fontSize: 13 }}>
                branch <span className="chip">{f.branch}</span>
              </div>
            ) : null}

            {f.diff ? (
              <div style={{ marginTop: 12 }}>
                <button className="btn sm" onClick={() => setOpen(open === f.id ? null : f.id)}>
                  {open === f.id ? 'Hide diff' : 'View diff'}
                </button>
                {open === f.id ? <DiffView diff={f.diff} /> : null}
              </div>
            ) : f.manualSteps.length ? (
              <div style={{ marginTop: 12 }}>
                <button className="btn sm" onClick={() => setOpen(open === f.id ? null : f.id)}>
                  {open === f.id ? 'Hide steps' : 'View steps'}
                </button>
                {open === f.id ? (
                  <ol className="muted" style={{ marginTop: 10, fontSize: 14 }}>
                    {f.manualSteps.map((s, i) => (
                      <li key={i}>{s}</li>
                    ))}
                  </ol>
                ) : null}
              </div>
            ) : null}
          </div>
        ))}
        {fixes && fixes.length === 0 ? <Empty>No remediations proposed for this run.</Empty> : null}
      </div>
    </>
  );
}
