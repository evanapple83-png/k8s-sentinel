import 'server-only';
import { supabaseAdmin } from './supabase/server';
import type { PostureSnapshot } from './wire';
import type {
  Account,
  AttackPath,
  AuditEntry,
  Cluster,
  Finding,
  Fix,
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

  const [{ data: findings }, { data: paths }, { data: fixes }] = await Promise.all([
    db.from('finding').select('*').eq('run_id', runId),
    db.from('attack_path').select('*').eq('run_id', runId),
    db.from('remediation').select('*').eq('run_id', runId).order('priority', { ascending: false }),
  ]);

  return {
    run: mapRun(run),
    findings: (findings ?? []).map(mapFinding),
    paths: (paths ?? []).map(mapPath),
    fixes: (fixes ?? []).map(mapFix),
  };
}

/**
 * Ingest a posture push from the relay (hybrid mode, fase 2). NOT user-scoped:
 * the relay authenticated the agent and the ingest route authenticated the
 * relay; the account is resolved from the cluster. Idempotent — re-ingesting a
 * run replaces its findings/paths/remediations and mirrors only new audit
 * entries. Stores normalized posture only (DATA-BOUNDARY.md): no secrets, no
 * raw manifests, no credentials.
 */
export async function ingestSnapshot(
  clusterId: string,
  snap: PostureSnapshot,
): Promise<{ runId: string; accountId: string }> {
  const db = supabaseAdmin();

  const { data: cluster, error: cErr } = await db
    .from('cluster')
    .select('id, account_id')
    .eq('id', clusterId)
    .maybeSingle();
  if (cErr) throw cErr;
  if (!cluster) throw new AccessError('unknown cluster');
  const accountId = cluster.account_id as string;
  const runId = snap.run.id;

  const { error: rErr } = await db.from('run').upsert(
    {
      id: runId,
      cluster_id: clusterId,
      status: snap.run.status,
      engine: snap.run.engine,
      used_fixtures: snap.run.usedFixtures,
      finding_count: snap.run.findingCount,
      path_count: snap.run.pathCount,
      risk_score: snap.run.riskScore == null ? null : Math.round(snap.run.riskScore),
      summary: snap.run.summary,
      created_at: snap.run.startedAt,
    },
    { onConflict: 'id' },
  );
  if (rErr) throw rErr;

  // Replace child rows so a re-pushed run never accumulates duplicates.
  await Promise.all([
    db.from('finding').delete().eq('run_id', runId),
    db.from('attack_path').delete().eq('run_id', runId),
    db.from('remediation').delete().eq('run_id', runId),
  ]);

  if (snap.findings.length) {
    const { error } = await db.from('finding').insert(
      snap.findings.map((f) => ({
        id: f.id,
        run_id: runId,
        source: f.source,
        rule_id: f.ruleId,
        title: f.title,
        description: f.description ?? '',
        severity: f.severity,
        resource: f.resource,
        reachable: f.reachable ?? null,
        exploit_score: f.exploitScore == null ? null : Math.round(f.exploitScore),
        attack_path_id: f.attackPathId ?? null,
        controls: f.controls ?? null,
        base_score: f.baseScore ?? null,
      })),
    );
    if (error) throw error;
  }

  if (snap.paths.length) {
    const { error } = await db.from('attack_path').insert(
      snap.paths.map((p) => ({
        id: p.id,
        run_id: runId,
        narrative: p.narrative,
        score: Math.round(p.score),
        entry_point: p.entryPoint ?? null,
        steps: p.steps,
        finding_ids: p.findingIds,
      })),
    );
    if (error) throw error;
  }

  if (snap.remediations.length) {
    const { error } = await db.from('remediation').insert(
      snap.remediations.map((m) => ({
        id: m.id,
        run_id: runId,
        playbook_id: m.playbookId,
        title: m.title,
        severity: m.severity,
        kind: m.kind,
        rationale: m.rationale,
        path: m.path,
        diff: m.diff,
        manual_steps: m.manualSteps,
        controls: m.controls,
        finding_ids: m.findingIds,
        attack_path_id: m.attackPathId ?? null,
        priority: Math.round(m.priority),
        branch: m.branch,
        pr_title: m.prTitle,
        pr_body: m.prBody,
      })),
    );
    if (error) throw error;
  }

  // Mirror only NEW audit entries (idempotent; seq is unique within the run).
  if (snap.audit.length) {
    const seqs = snap.audit.map((a) => a.seq);
    const { data: existing } = await db.from('audit_entry').select('seq').eq('run_id', runId).in('seq', seqs);
    const have = new Set((existing ?? []).map((e) => Number(e.seq)));
    const toInsert = snap.audit
      .filter((a) => !have.has(a.seq))
      .map((a) => ({
        account_id: accountId,
        cluster_id: clusterId,
        run_id: runId,
        seq: a.seq,
        ts: a.ts,
        actor: a.actor,
        agent: a.agent ?? null,
        action: a.action,
        detail: null,
      }));
    if (toInsert.length) {
      const { error } = await db.from('audit_entry').insert(toInsert);
      if (error) throw error;
    }
  }

  await db
    .from('cluster')
    .update({ last_seen_at: new Date().toISOString(), status: 'connected' })
    .eq('id', clusterId);

  return { runId, accountId };
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

function mapFix(r: Record<string, unknown>): Fix {
  return {
    id: r.id as string,
    playbookId: r.playbook_id as string,
    title: r.title as string,
    severity: r.severity as Fix['severity'],
    kind: r.kind as Fix['kind'],
    rationale: (r.rationale as string) ?? '',
    path: (r.path as string) ?? '',
    diff: (r.diff as string) ?? '',
    manualSteps: (r.manual_steps as string[]) ?? [],
    controls: (r.controls as Fix['controls']) ?? [],
    findingIds: (r.finding_ids as string[]) ?? [],
    attackPathId: (r.attack_path_id as string) ?? undefined,
    priority: Number(r.priority ?? 0),
    status: 'proposed',
    branch: (r.branch as string) ?? '',
    prTitle: (r.pr_title as string) ?? '',
    prBody: (r.pr_body as string) ?? '',
  };
}
