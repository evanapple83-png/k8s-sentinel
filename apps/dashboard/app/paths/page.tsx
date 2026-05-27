'use client';

import { Fragment } from 'react';
import { useSnapshot } from '@/lib/run-context';
import { Empty, PageHeader, scoreBucket } from '@/components/ui';

export default function PathsPage() {
  const { data, loading } = useSnapshot();

  if (!loading && !data) {
    return (
      <>
        <PageHeader title="Attack Paths" />
        <Empty>No run selected. Run a scan on the Overview screen.</Empty>
      </>
    );
  }

  const paths = data ? [...data.paths].sort((a, b) => b.score - a.score) : [];

  return (
    <>
      <PageHeader
        title="Attack Paths"
        sub="Correlated chains — exposed → running → vulnerable → over-privileged → secret-access."
      />

      {paths.length === 0 ? (
        <Empty>No correlated attack paths — nothing both reachable and exploitable.</Empty>
      ) : null}

      <div className="grid" style={{ gap: 16 }}>
        {paths.map((p) => (
          <div className="card" key={p.id}>
            <div className="row between">
              <span className={`score ${scoreBucket(p.score)}`} style={{ fontSize: 22 }}>
                {p.score}/100
              </span>
              <span className="pill">{p.entryPoint ?? 'in-cluster'} entry</span>
            </div>
            <p style={{ margin: '10px 0 0' }}>{p.narrative}</p>

            <div className="chain">
              <div className="step" style={{ background: 'rgba(10,132,255,0.10)' }}>
                <div className="kind">entry</div>
                <div className="res">{p.entryPoint ?? 'in-cluster'}</div>
              </div>
              {p.steps.map((s, i) => (
                <Fragment key={`${p.id}-${i}`}>
                  <div className="arrow">→</div>
                  <div className="step">
                    <div className="kind">{s.kind}</div>
                    <div className="res">
                      {s.resource.kind} {s.resource.namespace ? `${s.resource.namespace}/` : ''}
                      {s.resource.name}
                    </div>
                    <div className="det">{s.detail}</div>
                  </div>
                </Fragment>
              ))}
            </div>

            <div className="muted" style={{ marginTop: 12, fontSize: 13 }}>
              {p.findingIds.length} finding{p.findingIds.length === 1 ? '' : 's'} in this chain
            </div>
          </div>
        ))}
      </div>
    </>
  );
}
