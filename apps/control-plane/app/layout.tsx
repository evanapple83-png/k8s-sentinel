import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import './globals.css';
import { AppShell } from '@/components/app-shell';

export const metadata: Metadata = {
  title: 'K8s Sentinel — Control Plane',
  description:
    'Hosted security posture for your Kubernetes clusters. The agent stays in your cluster; only findings, attack paths, and audit metadata flow here.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
