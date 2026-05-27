'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { ReactNode } from 'react';
import { RunProvider, useRuns } from '@/lib/run-context';

const NAV = [
  { href: '/', label: 'Overview', ico: '◎' },
  { href: '/findings', label: 'Findings', ico: '▤' },
  { href: '/paths', label: 'Attack Paths', ico: '⛓' },
  { href: '/ask', label: 'Ask', ico: '⌕' },
  { href: '/report', label: 'Report', ico: '▦' },
  { href: '/fixes', label: 'Fixes', ico: '✓' },
];

function isActive(pathname: string, href: string): boolean {
  return href === '/' ? pathname === '/' : pathname.startsWith(href);
}

function Sidebar() {
  const pathname = usePathname();
  const { runs, runId, setRunId, error } = useRuns();

  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="glyph">K</span>
        <span>
          K8s Sentinel
        </span>
      </div>
      <nav className="nav">
        {NAV.map((n) => (
          <Link key={n.href} href={n.href} className={isActive(pathname, n.href) ? 'active' : ''}>
            <span className="ico">{n.ico}</span>
            {n.label}
          </Link>
        ))}
      </nav>

      <div className="spacer" />

      {error ? (
        <div className="banner" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
          <strong>API offline</strong>
          <span className="muted">Run `sentinel serve`, then reload.</span>
        </div>
      ) : null}

      <label className="section-label" style={{ margin: '0 10px 6px' }}>
        Active run
      </label>
      <select
        className="input"
        value={runId ?? ''}
        onChange={(e) => setRunId(e.target.value)}
        disabled={runs.length === 0}
      >
        {runs.length === 0 ? <option value="">no runs yet</option> : null}
        {runs.map((r) => (
          <option key={r.id} value={r.id}>
            {r.id.replace('run-', '#')} · risk {r.riskScore ?? '–'}
          </option>
        ))}
      </select>
    </aside>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  return (
    <RunProvider>
      <div className="app">
        <Sidebar />
        <main className="main">{children}</main>
      </div>
    </RunProvider>
  );
}
