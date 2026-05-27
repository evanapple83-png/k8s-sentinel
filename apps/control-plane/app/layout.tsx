import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { AppShell, type ShellNav, type ShellUser } from '@/components/app-shell';
import { themeInitScript } from '@/components/theme-toggle';
import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';
import { getActiveData } from '@/lib/active';

export const metadata: Metadata = {
  title: 'K8s Sentinel — Control Plane',
  description:
    'Hosted security posture for your Kubernetes clusters. The agent stays in your cluster; only findings, attack paths, and audit metadata flow here.',
};

const runLabel = (createdAt: string, risk: number | null) => {
  const when = new Date(createdAt).toLocaleString('en-GB', {
    day: '2-digit',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  });
  return risk == null ? when : `${when} · risk ${risk}`;
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  const session = authEnabled() ? await auth() : null;
  const user: ShellUser = session?.user
    ? {
        name: session.user.name ?? session.user.email ?? 'User',
        email: session.user.email ?? '',
        role: session.user.role ?? session.user.maxRole ?? 'viewer',
      }
    : null;

  // Picker options come from the same tenant data layer the screens use. The
  // layout has no searchParams, so this resolves the default selection; the
  // client shell reflects any explicit ?account/?cluster/?run from the URL.
  const data = await getActiveData(undefined);
  const nav: ShellNav = data.demo
    ? { ...DEMO_NAV }
    : {
        demo: false,
        accounts: data.accounts.map((a) => ({ id: a.account.id, name: a.account.name })),
        clusters: data.clusters.map((c) => ({ id: c.id, name: c.name, status: c.status })),
        runs: data.runs.map((r) => ({ id: r.id, label: runLabel(r.createdAt, r.riskScore) })),
        activeAccountId: data.activeAccountId,
        activeClusterId: data.activeClusterId,
        activeRunId: data.activeRunId,
      };

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body>
        <AppShell user={user} nav={nav}>
          {children}
        </AppShell>
      </body>
    </html>
  );
}

const DEMO_NAV: ShellNav = {
  demo: true,
  accounts: [],
  clusters: [],
  runs: [],
  activeAccountId: null,
  activeClusterId: null,
  activeRunId: null,
};
