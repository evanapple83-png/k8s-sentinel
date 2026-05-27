import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { AppShell, type ShellUser } from '@/components/app-shell';
import { themeInitScript } from '@/components/theme-toggle';
import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';

export const metadata: Metadata = {
  title: 'K8s Sentinel — Control Plane',
  description:
    'Hosted security posture for your Kubernetes clusters. The agent stays in your cluster; only findings, attack paths, and audit metadata flow here.',
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

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeInitScript }} />
      </head>
      <body>
        <AppShell user={user}>{children}</AppShell>
      </body>
    </html>
  );
}
