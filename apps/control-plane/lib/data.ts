import 'server-only';
import { supabaseAdmin } from './supabase/server';
import type {
  Account,
  AttackPath,
  AuditEntry,
  Cluster,
  Finding,
  Membership,
  Role,
  RunRecord,
  RunSnapshot,
} from './types';

/**
 * Tenant-scoped data layer.
 *
 * The secret-key client bypasses RLS, so THIS module is where tenant isolation
 * is enforced: every account-scoped read/write goes through `requireMembership`
 * first. Callers pass the signed-in user id + the active account id; a user who
 * isn't a member of that account gets a thrown `AccessError` and zero data.
 */

export class AccessError extends Error {
  constructor(message = 'forbidden') {
    super(message);
    this.name = 'AccessError';
  }
}

const ROLE_RANK: Record<Role, number> = { viewer: 0, approver: 1, admin: 2 };

// --- Identity / membership --------------------------------------------------

/** Upsert the NextAuth user into app_user and return its id (called on sign-in). */
export async function ensureUser(input: {
  email: string;
  name?: string | null;
  image?: string | null;
}): Promise<string> {
  const db = supabaseAdmin();
  const { data, error } = await db
    .from('app_user')
    .upsert({ email: input.email, name: input.name, image: input.image }, { onConflict: 'email' })
    .select('id')
    .single();
  if (error) throw error;
  return data.id as string;
}

/** The membership guard. Throws AccessError if the user is not in the account. */
export async function requireMembership(userId: string, accountId: string): Promise<Membership> {
  const db = supabaseAdmin();
  const { data, error } = await db
    .from('membership')
    .select('account_id, user_id, role, mfa_enrolled')
    .eq('account_id', accountId)
    .eq('user_id', userId)
    .maybeSingle();
  if (error) throw error;
  if (!data) throw new AccessError();
  return {
    accountId: data.account_id,
    userId: data.user_id,
    role: data.role as Role,
    mfaEnrolled: data.mfa_enrolled,
  };
}

/** Assert the user holds at least `min` role in the account (e.g. 'approver'). */
export async function requireRole(
  userId: string,
  accountId: string,
  min: Role,
): Promise<Membership> {
  const m = await requireMembership(userId, accountId);
  if (ROLE_RANK[m.role] < ROLE_RANK[min]) throw new AccessError(`requires ${min}`);
  return m;
}

/** All accounts the user belongs to, with their role. */
export async function listAccountsForUser(
  userId: string,
): Promise<Array<{ account: Account; role: Role }>> {
  const db = supabaseAdmin();
  const { data, error } = await db
    .from('membership')
    .select('role, account:account_id (id, name, slug, created_at)')
    .eq('user_id', userId);
  if (error) throw error;
  return (data ?? []).flatMap((row) => {
    const a = row.account as unknown as {
      id: string;
      name: string;
      slug: string;
      created_at: string;
    } | null;
    if (!a) return [];
    return [
      {
        role: row.role as Role,
        account: { id: a.id, name: a.name, createdAt: a.created_at },
      },
    ];
  });
}

// --- Clusters ---------------------------------------------------------------

export async function listClusters(userId: string, accountId: string): Promise<Cluster[]> {
  await requireMembership(userId, accountId);
  const db = supabaseAdmin();
  const { data, error } = await db
    .from('cluster')
    .select('*')
    .eq('account_id', accountId)
    .order('created_at', { ascending: false });
  if (error) throw error;
  return (data ?? []).map(mapCluster);
}

// --- Runs / findings / paths ------------------------------------------------

export async function listRuns(
  userId: string,
  accountId: string,
  clusterId: string,
): Promise<RunRecord[]> {
  await requireMembership(userId, accountId);
  const db = supabaseAdmin();
  // Confirm the cluster is in this account before listing its runs.
  const { data: cl } = await db
    .from('cluster')
    .select('id')
    .eq('id', clusterId)
    .eq('account_id', accountId)
    .maybeSingle();
  if (!cl) throw new AccessError('cluster not in account');

  const { data, error } = await db
    .from('run')
    .select('*')
    .eq('cluster_id', clusterId)
    .order('created_at', { ascending: false });
  if (error) throw error;
  return (data ?? []).map(mapRun);
}

export async function getRunSnapshot(
  userId: string,
  accountId: string,
  runId: string,
): Promise<RunSnapshot | null> {
  await requireMembership(userId, accountId);
  const db = supabaseAdmin();

  // Join run → cluster to verify the run belongs to this account.
  const { data: run, error: runErr } = await db
    .from('run')
    .select('*, cluster:cluster_id!inner (account_id)')
    .eq('id', runId)
    .maybeSingle();
  if (runErr) throw runErr;
  if (!run || (run.cluster as { account_id: string }).account_id !== accountId) {
    return null;
  }

  const [{ data: findings }, { data: paths }] = await Promise.all([
    db.from('finding').select('*').eq('run_id', runId),
    db.from('attack_path').select('*').eq('run_id', runId),
  ]);

  return {
    run: mapRun(run),
    findings: (findings ?? []).map(mapFinding),
    paths: (paths ?? []).map(mapPath),
    fixes: [], // proposals are streamed in a later phase
  };
}

// --- Audit ------------------------------------------------------------------

export async function listAudit(
  userId: string,
  accountId: string,
  limit = 100,
): Promise<AuditEntry[]> {
  await requireMembership(userId, accountId);
  const db = supabaseAdmin();
  const { data, error } = await db
    .from('audit_entry')
    .select('seq, ts, actor, agent, action, run_id')
    .eq('account_id', accountId)
    .order('ts', { ascending: false })
    .limit(limit);
  if (error) throw error;
  return (data ?? []).map((r) => ({
    seq: Number(r.seq ?? 0),
    ts: r.ts,
    actor: r.actor,
    agent: r.agent ?? undefined,
    action: r.action,
    runId: r.run_id ?? undefined,
  }));
}

/** Append an audit entry (control-plane side actions: role change, token mint…). */
export async function recordAudit(input: {
  accountId: string;
  actor: string;
  action: string;
  clusterId?: string;
  runId?: string;
  detail?: Record<string, unknown>;
}): Promise<void> {
  const db = supabaseAdmin();
  const { error } = await db.from('audit_entry').insert({
    account_id: input.accountId,
    actor: input.actor,
    action: input.action,
    cluster_id: input.clusterId ?? null,
    run_id: input.runId ?? null,
    detail: input.detail ?? null,
  });
  if (error) throw error;
}

// --- Auth provisioning + context (used by NextAuth callbacks) ---------------

export interface AuthContext {
  userId: string;
  maxRole: Role;
  mfaRequired: boolean;
  mfaEnrolled: boolean;
  activeAccountId: string | null;
  activeRole: Role | null;
}

/**
 * Ensure the signed-in user exists and belongs to at least one account. A brand
 * new user is bootstrapped into a personal workspace as admin so they land
 * somewhere; real org onboarding/invites come in 1E.
 */
export async function provisionUser(input: {
  email: string;
  name?: string | null;
  image?: string | null;
}): Promise<string> {
  const userId = await ensureUser(input);
  const accounts = await listAccountsForUser(userId);
  if (accounts.length === 0) {
    const db = supabaseAdmin();
    const name = input.name ? `${input.name}'s workspace` : `${input.email.split('@')[0]}'s workspace`;
    const slug = `ws-${userId.slice(0, 8)}`;
    const { data: acc, error } = await db
      .from('account')
      .insert({ name, slug })
      .select('id')
      .single();
    if (error) throw error;
    const { error: mErr } = await db
      .from('membership')
      .insert({ account_id: acc.id, user_id: userId, role: 'admin' });
    if (mErr) throw mErr;
    await recordAudit({
      accountId: acc.id,
      actor: input.email,
      action: 'account.bootstrapped',
      detail: { role: 'admin' },
    });
  }
  return userId;
}

/** Resolve role + MFA status for the JWT/session (no account scoping needed). */
export async function getAuthContext(userId: string): Promise<AuthContext> {
  const accounts = await listAccountsForUser(userId);
  const maxRole = accounts.reduce<Role>(
    (m, a) => (ROLE_RANK[a.role] > ROLE_RANK[m] ? a.role : m),
    'viewer',
  );
  const active = accounts[0] ?? null;
  const db = supabaseAdmin();
  const { data: u } = await db
    .from('app_user')
    .select('mfa_enrolled')
    .eq('id', userId)
    .maybeSingle();
  return {
    userId,
    maxRole,
    mfaRequired: ROLE_RANK[maxRole] >= ROLE_RANK.approver,
    mfaEnrolled: Boolean(u?.mfa_enrolled),
    activeAccountId: active?.account.id ?? null,
    activeRole: active?.role ?? null,
  };
}

export async function getMfaState(userId: string): Promise<{ secret: string | null; enrolled: boolean }> {
  const db = supabaseAdmin();
  const { data, error } = await db
    .from('app_user')
    .select('mfa_secret, mfa_enrolled')
    .eq('id', userId)
    .maybeSingle();
  if (error) throw error;
  return { secret: data?.mfa_secret ?? null, enrolled: Boolean(data?.mfa_enrolled) };
}

/** Store a freshly generated secret (not yet enrolled until first verify). */
export async function setMfaSecret(userId: string, secret: string): Promise<void> {
  const db = supabaseAdmin();
  const { error } = await db
    .from('app_user')
    .update({ mfa_secret: secret, mfa_enrolled: false })
    .eq('id', userId);
  if (error) throw error;
}

export async function markMfaEnrolled(userId: string, actorEmail: string): Promise<void> {
  const db = supabaseAdmin();
  const { error } = await db.from('app_user').update({ mfa_enrolled: true }).eq('id', userId);
  if (error) throw error;
  const accounts = await listAccountsForUser(userId);
  if (accounts[0]) {
    await recordAudit({
      accountId: accounts[0].account.id,
      actor: actorEmail,
      action: 'mfa.enrolled',
    });
  }
}

// --- Row mappers (snake_case DB → camelCase domain) -------------------------

function mapCluster(r: Record<string, unknown>): Cluster {
  return {
    id: r.id as string,
    accountId: r.account_id as string,
    name: r.name as string,
    status: r.status as Cluster['status'],
    mode: r.mode as Cluster['mode'],
    agentVersion: (r.agent_version as string) ?? null,
    lastSeenAt: (r.last_seen_at as string) ?? null,
    connectedAt: (r.connected_at as string) ?? null,
    createdAt: r.created_at as string,
  };
}

function mapRun(r: Record<string, unknown>): RunRecord {
  return {
    id: r.id as string,
    clusterId: r.cluster_id as string,
    createdAt: r.created_at as string,
    status: r.status as RunRecord['status'],
    engine: r.engine as string,
    usedFixtures: Boolean(r.used_fixtures),
    findingCount: Number(r.finding_count ?? 0),
    pathCount: Number(r.path_count ?? 0),
    riskScore: r.risk_score == null ? null : Number(r.risk_score),
    summary: (r.summary as string) ?? null,
  };
}

function mapFinding(r: Record<string, unknown>): Finding {
  return {
    id: r.id as string,
    source: r.source as string,
    ruleId: r.rule_id as string,
    title: r.title as string,
    description: (r.description as string) ?? '',
    severity: r.severity as Finding['severity'],
    resource: (r.resource as Finding['resource']) ?? { kind: '', name: '' },
    reachable: (r.reachable as boolean) ?? undefined,
    exploitScore: r.exploit_score == null ? undefined : Number(r.exploit_score),
    attackPathId: (r.attack_path_id as string) ?? undefined,
    controls: (r.controls as Finding['controls']) ?? undefined,
    baseScore: r.base_score == null ? undefined : Number(r.base_score),
  };
}

function mapPath(r: Record<string, unknown>): AttackPath {
  return {
    id: r.id as string,
    narrative: r.narrative as string,
    score: Number(r.score ?? 0),
    entryPoint: (r.entry_point as string) ?? undefined,
    steps: (r.steps as AttackPath['steps']) ?? [],
    findingIds: (r.finding_ids as string[]) ?? [],
  };
}
