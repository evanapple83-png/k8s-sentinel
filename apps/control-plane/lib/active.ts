import 'server-only';
import { auth } from '@/auth';
import { authEnabled } from '@/auth.config';
import { supabaseConfigured } from './supabase/server';
import {
  getRunSnapshot,
  listAccountsForUser,
  listClusters,
  listRuns,
} from './data';
import { DEMO_SNAPSHOT } from './mock';
import type { Account, Cluster, Role, RunRecord, RunSnapshot } from './types';

/**
 * Resolves what the 6 screens actually render.
 *
 * Dual-mode by design (the single most important property of 1D):
 *   - DEMO   — auth off OR Supabase unconfigured OR no signed-in user. Returns
 *              the offline payment-api dataset so the hosted preview works with
 *              zero env.
 *   - LIVE   — auth on + Supabase configured + signed-in user. Resolves the
 *              tenant-scoped snapshot via `lib/data.ts` (the chokepoint), scoped
 *              to the active account/cluster/run picked from the URL or defaults.
 *
 * Any DB/access failure degrades to an empty live state (or demo) rather than a
 * 500 — tenant isolation still holds because every read goes through the data
 * layer's membership guard.
 */

export type ActiveData =
  | {
      demo: true;
      snapshot: RunSnapshot;
      accounts: Array<{ account: Account; role: Role }>;
      clusters: Cluster[];
      runs: RunRecord[];
      activeAccountId: null;
      activeClusterId: null;
      activeRunId: null;
    }
  | {
      demo: false;
      snapshot: RunSnapshot | null;
      accounts: Array<{ account: Account; role: Role }>;
      clusters: Cluster[];
      runs: RunRecord[];
      activeAccountId: string | null;
      activeClusterId: string | null;
      activeRunId: string | null;
    };

type RawSearchParams = Record<string, string | string[] | undefined>;
export type SearchParamsInput =
  | RawSearchParams
  | Promise<RawSearchParams>
  | undefined;

function first(v: string | string[] | undefined): string | undefined {
  return Array.isArray(v) ? v[0] : v;
}

function demoResult(): ActiveData {
  return {
    demo: true,
    snapshot: DEMO_SNAPSHOT,
    accounts: [],
    clusters: [],
    runs: [],
    activeAccountId: null,
    activeClusterId: null,
    activeRunId: null,
  };
}

export async function getActiveData(
  searchParams?: SearchParamsInput,
): Promise<ActiveData> {
  // Demo mode: no auth, no Supabase, or not signed in.
  if (!authEnabled() || !supabaseConfigured()) return demoResult();

  const session = await auth();
  const userId = session?.user?.id;
  if (!userId) return demoResult();

  const params: RawSearchParams = searchParams ? await searchParams : {};
  const wantAccount = first(params.account);
  const wantCluster = first(params.cluster);
  const wantRun = first(params.run);

  // Empty live shell to fall back to when the account/cluster has no data yet,
  // or when a read is denied — never leak demo data into a real session.
  const emptyLive = (
    accounts: ActiveData['accounts'],
    clusters: Cluster[],
    runs: RunRecord[],
    ids: { account: string | null; cluster: string | null; run: string | null },
  ): ActiveData => ({
    demo: false,
    snapshot: null,
    accounts,
    clusters,
    runs,
    activeAccountId: ids.account,
    activeClusterId: ids.cluster,
    activeRunId: ids.run,
  });

  try {
    const accounts = await listAccountsForUser(userId);
    if (accounts.length === 0) {
      return emptyLive([], [], [], { account: null, cluster: null, run: null });
    }

    const activeAccountId =
      (wantAccount && accounts.some((a) => a.account.id === wantAccount)
        ? wantAccount
        : undefined) ?? accounts[0]!.account.id;

    const clusters = await listClusters(userId, activeAccountId);
    if (clusters.length === 0) {
      return emptyLive(accounts, [], [], {
        account: activeAccountId,
        cluster: null,
        run: null,
      });
    }

    // Explicit ?cluster= wins; otherwise prefer the newest CONNECTED cluster so
    // the dashboard (and its "Run scan" button) land on a live agent rather than
    // a stale/ghost cluster from an earlier onboard. Falls back to newest. (F11)
    const activeClusterId =
      (wantCluster && clusters.some((c) => c.id === wantCluster) ? wantCluster : undefined) ??
      clusters.find((c) => c.status === 'connected')?.id ??
      clusters[0]!.id;

    const runs = await listRuns(userId, activeAccountId, activeClusterId);
    if (runs.length === 0) {
      return emptyLive(accounts, clusters, [], {
        account: activeAccountId,
        cluster: activeClusterId,
        run: null,
      });
    }

    const activeRunId =
      (wantRun && runs.some((r) => r.id === wantRun) ? wantRun : undefined) ??
      runs[0]!.id;

    const snapshot = await getRunSnapshot(userId, activeAccountId, activeRunId);
    return {
      demo: false,
      snapshot,
      accounts,
      clusters,
      runs,
      activeAccountId,
      activeClusterId,
      activeRunId,
    };
  } catch (err) {
    // AccessError or an unreachable DB → degrade to the empty live shell so the
    // screen shows a calm empty state instead of a 500. Tenant isolation is
    // preserved (the guard threw rather than returning foreign data).
    console.error('[active] live data resolution failed:', err);
    return emptyLive([], [], [], { account: null, cluster: null, run: null });
  }
}
