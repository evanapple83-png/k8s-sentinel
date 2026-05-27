'use client';

import { useMemo, useState } from 'react';
import { useSnapshot } from '@/lib/run-context';
import type { Severity } from '@/lib/types';
import { Dot, Empty, PageHeader, ResourceLabel } from '@/components/ui';

const SEV_FILTERS: Array<Severity | 'all'> = ['all', 'critical', 'high', 'medium', 'low'];

export default function FindingsPage() {
  const { data, loading } = useSnapshot();
  const [sev, setSev] = useState<Severity | 'all'>('all');
  const [source, setSource] = useState<string>('all');
  const [reachableOnly, setReachableOnly] = useState(false);
  const [q, setQ] = useState('');

  const sources = useMemo(
    () => (data ? Array.from(new Set(data.findings.map((f) => f.source))).sort() : []),
    [data],
  );

  const findings = useMemo(() => {
    if (!data) return [];
    const needle = q.trim().toLowerCase();
    return [...data.findings]
      .filter((f) => (sev === 'all' ? true : f.severity === sev))
      .filter((f) => (source === 'all' ? true : f.source === source))
      .filter((f) => (reachableOnly ? f.reachable : true))
      .filter((f) =>
        needle
          ? `${f.title} ${f.ruleId} ${f.resource.name} ${f.resource.namespace ?? ''}`
              .toLowerCase()
              .includes(needle)
          : true,
      )
      .sort((a, b) => (b.exploitScore ?? 0) - (a.exploitScore ?? 0));
  }, [data, sev, source, reachableOnly, q]);

  if (!loading && !data) {
    return (
      <>
        <PageHeader title="Findings" />
        <Empty>No run selected. Run a scan on the Overview screen.</Empty>
      </>
    );
  }

  return (
    <>
      <PageHeader title="Findings" sub="Ranked by exploitability — reachability-weighted, not raw CVSS." />

      <div className="toolbar">
        {SEV_FILTERS.map((s) => (
          <button
            key={s}
            className={`btn sm ${sev === s ? 'primary' : ''}`}
            onClick={() => setSev(s)}
          >
            {s}
          </button>
        ))}
        <select className="input" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="all">all scanners</option>
          {sources.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <button
          className={`btn sm ${reachableOnly ? 'primary' : ''}`}
          onClick={() => setReachableOnly((v) => !v)}
        >
          reachable only
        </button>
        <input
          className="input"
          placeholder="Search title, rule, resource…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ flex: 1, minWidth: 180 }}
        />
      </div>

      <div className="card">
        <div className="muted" style={{ marginBottom: 6, fontSize: 13 }}>
          {findings.length} finding{findings.length === 1 ? '' : 's'}
        </div>
        <div className="list">
          {findings.map((f) => (
            <div className="fitem" key={f.id}>
              <span className="score" style={{ textAlign: 'right' }}>
                {f.exploitScore ?? 0}
              </span>
              <Dot sev={f.severity} />
              <div>
                <div className="title">{f.title}</div>
                <div className="meta">
                  <span className="chip">{f.source}</span> {f.ruleId} · <ResourceLabel resource={f.resource} />
                </div>
              </div>
              <div className="row" style={{ gap: 8 }}>
                {f.reachable ? <span className="reach">reachable</span> : null}
                {(f.controls ?? []).slice(0, 2).map((c) => (
                  <span key={c.id} className="chip">
                    {c.id}
                  </span>
                ))}
              </div>
            </div>
          ))}
          {findings.length === 0 ? <div className="empty">No findings match these filters.</div> : null}
        </div>
      </div>
    </>
  );
}
