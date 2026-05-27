'use client';

import Link from 'next/link';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { Suspense, type ReactNode } from 'react';
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
import { LogOut } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ThemeToggle } from '@/components/theme-toggle';
import { doSignOut } from '@/app/actions';

export type ShellUser = { name: string; email: string; role: string } | null;

/** Minimal, serializable picker options passed from the server layout. */
export interface ShellNav {
  demo: boolean;
  accounts: Array<{ id: string; name: string }>;
  clusters: Array<{ id: string; name: string; status: string }>;
  runs: Array<{ id: string; label: string }>;
  activeAccountId: string | null;
  activeClusterId: string | null;
  activeRunId: string | null;
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

/** Neutral, disabled picker shells shown while LivePickers suspends. */
function PickerSkeleton() {
  return (
    <>
      {(['Account', 'Cluster', 'Active run'] as const).map((label) => (
        <Picker key={label} label={label}>
          <select className={selectCls} disabled>
            <option>…</option>
          </select>
        </Picker>
      ))}
    </>
  );
}

/** Demo pickers — disabled preview values + hint. No URL/router reads. */
function DemoPickers() {
  return (
    <>
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
        Showing <span className="font-medium text-foreground">demo data</span> — connect a cluster
        for live results.
      </div>
    </>
  );
}

/**
 * Live pickers. Isolated so the `useSearchParams` CSR bailout is contained to a
 * <Suspense> boundary (it would otherwise opt the whole static shell out of
 * prerendering, breaking the demo build).
 */
function LivePickers({ nav }: { nav: ShellNav }) {
  const pathname = usePathname();
  const router = useRouter();
  const searchParams = useSearchParams();

  // The selected value reflects the URL first (the user's explicit pick), then
  // the server-resolved default. The layout resolves option lists from the
  // defaults, so the displayed selection stays correct even on a deep link.
  const selected = (key: 'account' | 'cluster' | 'run', fallback: string | null) =>
    searchParams.get(key) ?? fallback ?? '';

  // Navigate to the same route with a swapped picker query param. Changing the
  // account/cluster resets the downstream selections so the server resolves a
  // fresh default.
  function pick(key: 'account' | 'cluster' | 'run', value: string) {
    const params = new URLSearchParams(searchParams.toString());
    params.set(key, value);
    if (key === 'account') {
      params.delete('cluster');
      params.delete('run');
    } else if (key === 'cluster') {
      params.delete('run');
    }
    router.push(`${pathname}?${params.toString()}`);
  }

  return (
    <>
      <Picker label="Account">
        <select
          className={selectCls}
          value={selected('account', nav.activeAccountId)}
          disabled={nav.accounts.length <= 1}
          onChange={(e) => pick('account', e.target.value)}
        >
          {nav.accounts.length === 0 ? <option value="">No accounts</option> : null}
          {nav.accounts.map((a) => (
            <option key={a.id} value={a.id}>
              {a.name}
            </option>
          ))}
        </select>
      </Picker>
      <Picker label="Cluster">
        <select
          className={selectCls}
          value={selected('cluster', nav.activeClusterId)}
          disabled={nav.clusters.length === 0}
          onChange={(e) => pick('cluster', e.target.value)}
        >
          {nav.clusters.length === 0 ? <option value="">No clusters</option> : null}
          {nav.clusters.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name} · {c.status}
            </option>
          ))}
        </select>
      </Picker>
      <Picker label="Active run">
        <select
          className={selectCls}
          value={selected('run', nav.activeRunId)}
          disabled={nav.runs.length === 0}
          onChange={(e) => pick('run', e.target.value)}
        >
          {nav.runs.length === 0 ? <option value="">No runs yet</option> : null}
          {nav.runs.map((r) => (
            <option key={r.id} value={r.id}>
              {r.label}
            </option>
          ))}
        </select>
      </Picker>
      {nav.clusters.length === 0 ? (
        <div className="rounded-md border border-dashed px-2.5 py-1.5 text-[11px] text-muted-foreground">
          No clusters connected —{' '}
          <Link href="/connect" className="font-medium text-foreground hover:underline">
            connect one
          </Link>{' '}
          to see live results.
        </div>
      ) : null}
    </>
  );
}

export function AppShell({
  children,
  user,
  nav = DEMO_NAV,
}: {
  children: ReactNode;
  user?: ShellUser;
  nav?: ShellNav;
}) {
  const pathname = usePathname();

  // Auth screens render without the app chrome.
  if (pathname.startsWith('/login') || pathname.startsWith('/mfa')) {
    return <>{children}</>;
  }

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

        {/* Account / cluster / run selection. Live mode (auth + Supabase +
            signed-in) drives these from the tenant data layer; demo mode keeps
            the disabled preview values + hint so the hosted preview works with
            zero env. */}
        <div className="space-y-2.5">
          {nav.demo ? (
            <DemoPickers />
          ) : (
            <Suspense fallback={<PickerSkeleton />}>
              <LivePickers nav={nav} />
            </Suspense>
          )}
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

        {user ? (
          <div className="flex items-center gap-2 border-t pt-3">
            <div className="grid size-8 shrink-0 place-items-center rounded-full bg-secondary text-xs font-semibold uppercase text-secondary-foreground">
              {user.name.slice(0, 2)}
            </div>
            <div className="min-w-0 flex-1 leading-tight">
              <div className="truncate text-xs font-medium">{user.name}</div>
              <div className="truncate text-[11px] capitalize text-muted-foreground">
                {user.role}
              </div>
            </div>
            <form action={doSignOut}>
              <button
                type="submit"
                aria-label="Sign out"
                className="flex size-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
              >
                <LogOut className="size-4" />
              </button>
            </form>
          </div>
        ) : null}
      </aside>

      <main className="min-w-0 px-8 py-7">{children}</main>
    </div>
  );
}
