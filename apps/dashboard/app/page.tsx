'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { api, API_BASE } from '@/lib/api';
import { useRuns, useSnapshot } from '@/lib/run-context';
import type { Finding, Severity } from '@/lib/types';
import { Empty, PageHeader, RiskRing, rating, scoreBucket } from '@/components/ui';
import { ScanButton } from '@/components/scan-button';

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function tally(findings: Finding[], key: (f: Finding) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const f of findings) {
    const k = key(f);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

export default function OverviewPage() {
  const { runs, runId, setRunId, reload, loading, error } = useRuns();
  const { data } = useSnapshot();

  // "What changed since last scan" — diff the current finding ids against the
  // chronologically previous run.
  const [delta, setDelta] = useState<{ added: number; resolved: number } | null>(null);
  useEffect(() => {
    if (!runId) return;
    const idx = runs.findIndex((r) => r.id === runId);
    const prev = idx >= 0 ? runs[idx + 1] : undefined;
    if (!prev || !data) {
      setDelta(null);
      return;
    }
    let active = true;
    api
      .run(prev.id)
      .then((prevSnap) => {
        if (!active) return;
        const now = new Set(data.findings.map((f) => f.id));
        const before = new Set(prevSnap.findings.map((f) => f.id));
        const added = [...now].filter((id) => !before.has(id)).length;
        const resolved = [...before].filter((id) => !now.has(id)).length;
        setDelta({ added, resolved });
      })
      .catch(() => active && setDelta(null));
    return () => {
      active = false;
    };
  }, [runId, runs, data]);

  const sev = useMemo(() => (data ? tally(data.findings, (f) => f.severity) : {}), [data]);
  const sources = useMemo(() => (data ? tally(data.findings, (f) => f.source) : {}), [data]);

  function onScanDone(id: string) {
    void reload().then(() => setRunId(id));
  }

  if (error) {
    return (
      <>
        <PageHeader title="Overview" />
        <Empty>
          <p>Can’t reach the orchestrator API at <span className="chip">{API_BASE}</span>.</p>
          <p className="muted">Start it with <span className="chip">pnpm --filter @k8s-sentinel/api sentinel serve</span> and reload.</p>
        </Empty>
      </>
    );
  }

  if (!loading && runs.length === 0) {
    return (
      <>
        <PageHeader title="Overview" sub="No scans yet — run the first one." />
        <div className="card">
          <ScanButton onDone={onScanDone} />
        </div>
      </>
    );
  }

  if (!data) {
    return (
      <>
        <PageHeader title="Overview" />
        <div className="card muted">Loading run…</div>
      </>
    );
  }

  const risk = data.run.riskScore ?? 0;
  const reachable = data.findings.filter((f) => f.reachable).length;
  const topPath = data.paths[0];

  return (
    <>
      <PageHeader title="Overview" sub={`Run ${data.run.id} · engine ${data.run.engine}`} />

      {data.run.usedFixtures ? (
        <div className="banner">⚠ Offline fixtures — no live cluster/scanners detected.</div>
      ) : null}

      <div className="card row between" style={{ gap: 28 }}>
        <div className="row" style={{ gap: 28 }}>
          <RiskRing value={risk} />
          <div>
            <div className="section-label" style={{ margin: 0 }}>
              {rating(risk)} risk
            </div>
            <p style={{ margin: '6px 0 12px', maxWidth: 460 }}>{data.run.summary}</p>
            <div className="row wrap" style={{ gap: 8 }}>
              {SEV_ORDER.filter((s) => sev[s]).map((s) => (
                <span key={s} className={`pill ${s}`}>
                  {sev[s]} {s}
                </span>
              ))}
            </div>
          </div>
        </div>
        <ScanButton onDone={onScanDone} />
      </div>

      <div className="grid cols-3" style={{ marginTop: 16 }}>
        <div className="card">
          <div className="section-label" style={{ margin: '0 0 8px' }}>
            Findings
          </div>
          <div style={{ fontSize: 30, fontWeight: 700 }}>{data.findings.length}</div>
          <div className="muted">{reachable} reachable</div>
        </div>
        <div className="card">
          <div className="section-label" style={{ margin: '0 0 8px' }}>
            Attack paths
          </div>
          <div style={{ fontSize: 30, fontWeight: 700 }}>{data.paths.length}</div>
          <div className="muted">correlated &amp; ranked</div>
        </div>
        <div className="card">
          <div className="section-label" style={{ margin: '0 0 8px' }}>
            Since last scan
          </div>
          {delta ? (
            <div className="row" style={{ gap: 16 }}>
              <span className="score crit" style={{ fontSize: 24 }}>
                +{delta.added}
              </span>
              <span className="score ok" style={{ fontSize: 24 }}>
                −{delta.resolved}
              </span>
            </div>
          ) : (
            <div className="muted">no prior run</div>
          )}
          <div className="muted">new · resolved</div>
        </div>
      </div>

      <div className="section-label">Scanners</div>
      <div className="card row wrap" style={{ gap: 10 }}>
        {Object.entries(sources).map(([s, n]) => (
          <span key={s} className="chip">
            {s} · {n}
          </span>
        ))}
      </div>

      {topPath ? (
        <>
          <div className="section-label">Highest-risk attack path</div>
          <Link href="/paths" className="card" style={{ display: 'block' }}>
            <div className="row between">
              <span className={`score ${scoreBucket(topPath.score)}`} style={{ fontSize: 20 }}>
                {topPath.score}/100
              </span>
              <span className="muted">from {topPath.entryPoint ?? 'in-cluster'} →</span>
            </div>
            <p style={{ margin: '8px 0 0' }}>{topPath.narrative}</p>
          </Link>
        </>
      ) : null}
    </>
  );
}
