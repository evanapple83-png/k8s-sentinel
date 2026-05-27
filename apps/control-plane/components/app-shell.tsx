'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import type { ReactNode } from 'react';
import {
  Activity,
  ListChecks,
  Link2,
  Search,
  FileText,
  Wrench,
  ShieldCheck,
  PlugZap,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { ThemeToggle } from '@/components/theme-toggle';

const NAV = [
  { href: '/', label: 'Overview', icon: Activity },
  { href: '/findings', label: 'Findings', icon: ListChecks },
  { href: '/paths', label: 'Attack Paths', icon: Link2 },
  { href: '/ask', label: 'Ask', icon: Search },
  { href: '/report', label: 'Report', icon: FileText },
  { href: '/fixes', label: 'Fixes', icon: Wrench },
];

const SECONDARY = [
  { href: '/connect', label: 'Connect cluster', icon: PlugZap },
  { href: '/permissions', label: 'Permissions', icon: ShieldCheck },
];

function isActive(pathname: string, href: string): boolean {
  return href === '/' ? pathname === '/' : pathname.startsWith(href);
}

function NavLink({
  href,
  label,
  icon: Icon,
  pathname,
}: {
  href: string;
  label: string;
  icon: typeof Activity;
  pathname: string;
}) {
  return (
    <Link
      href={href}
      className={cn(
        'flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors',
        isActive(pathname, href)
          ? 'bg-accent text-accent-foreground'
          : 'text-muted-foreground hover:bg-accent/60 hover:text-foreground',
      )}
    >
      <Icon className="size-4" />
      {label}
    </Link>
  );
}

function Picker({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block px-2">
      <span className="mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      {children}
    </label>
  );
}

const selectCls =
  'w-full rounded-md border bg-background px-2.5 py-1.5 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring';

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();

  return (
    <div className="grid min-h-dvh grid-cols-[260px_1fr]">
      <aside className="flex flex-col gap-4 border-r bg-card/40 p-4">
        <div className="flex items-center justify-between px-2 py-1">
          <div className="flex items-center gap-2.5">
            <span className="grid size-8 place-items-center rounded-lg bg-primary font-bold text-primary-foreground">
              K
            </span>
            <div className="leading-tight">
              <div className="text-sm font-semibold">K8s Sentinel</div>
              <div className="text-[11px] text-muted-foreground">Hosted control plane</div>
            </div>
          </div>
          <ThemeToggle />
        </div>

        {/* Account / cluster / run selection — wired to Supabase in 1D.
            Showing demo data so every screen previews the real product. */}
        <div className="space-y-2.5">
          <Picker label="Account">
            <select className={selectCls} disabled>
              <option>Acme Inc.</option>
            </select>
          </Picker>
          <Picker label="Cluster">
            <select className={selectCls} disabled>
              <option>prod-eu-1 · connected</option>
            </select>
          </Picker>
          <Picker label="Active run">
            <select className={selectCls} disabled>
              <option>27 May 09:14 · risk 100</option>
            </select>
          </Picker>
          <div className="rounded-md border border-dashed px-2.5 py-1.5 text-[11px] text-muted-foreground">
            Showing <span className="font-medium text-foreground">demo data</span> — connect a
            cluster for live results.
          </div>
        </div>

        <nav className="space-y-1">
          {NAV.map((n) => (
            <NavLink key={n.href} {...n} pathname={pathname} />
          ))}
        </nav>

        <div className="mt-auto space-y-1 border-t pt-3">
          {SECONDARY.map((n) => (
            <NavLink key={n.href} {...n} pathname={pathname} />
          ))}
        </div>
      </aside>

      <main className="min-w-0 px-8 py-7">{children}</main>
    </div>
  );
}
