'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { ConnectClient } from './connect-client';
import { PubkeyConnectClient } from './pubkey-client';

/**
 * Segmented control above the connect screen. Switches between the unchanged
 * Helm flow (left) and the new Public-key flow (right). Only rendered when
 * FEATURE_PUBKEY_CONNECT is on — see app/connect/page.tsx.
 *
 * Pure UI, no data fetching here — each tab manages its own state. Tabs are
 * mounted on demand (only the active one renders) so each tab starts cleanly
 * when switched in (no stale poller, no leaked timer).
 */
type Tab = 'helm' | 'pubkey';

export function ConnectTabs() {
  const [tab, setTab] = useState<Tab>('helm');

  return (
    <div className="space-y-4">
      <div
        role="tablist"
        aria-label="Connect method"
        className="inline-flex w-full rounded-lg border bg-muted/40 p-1 text-sm"
      >
        <TabButton active={tab === 'helm'} onClick={() => setTab('helm')}>
          Helm install
        </TabButton>
        <TabButton active={tab === 'pubkey'} onClick={() => setTab('pubkey')}>
          Public key
        </TabButton>
      </div>

      {tab === 'helm' ? <ConnectClient /> : <PubkeyConnectClient />}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={cn(
        'flex-1 rounded-md px-3 py-1.5 font-medium transition-colors',
        active ? 'bg-background text-foreground shadow-sm' : 'text-muted-foreground hover:text-foreground',
      )}
    >
      {children}
    </button>
  );
}
