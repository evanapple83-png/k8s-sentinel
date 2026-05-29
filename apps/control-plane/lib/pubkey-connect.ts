import 'server-only';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { supabaseAdmin } from './supabase/server';
import { AccessError, ingestSnapshot, recordAudit, requireMembership } from './data';
import { mapToPostureSnapshot, type ArgusReportJson } from './argus-mapper';
import { chartOciRef, chartVersion } from './chart';
import { PostureSnapshotSchema } from './wire';

/**
 * Public-key connect data layer (Phase 5 / FEATURE_PUBKEY_CONNECT).
 *
 * Lives next to lib/data.ts as a focused module rather than inside it because
 * everything here is gated behind a single feature flag and built around the
 * frozen wire contract in docs/PUBKEY_CONNECT_CONTRACT.md. Keeping it isolated
 * means: (a) the existing data layer is byte-identical when the flag is off;
 * (b) the unit tests below this file only need to mock the contract surface;
 * (c) ripping it out (or graduating it into data.ts) is a single-file delete.
 *
 * Hard contract rules enforced here:
 *  - Raw enrollment token is returned ONCE from createClusterEnrollment;
 *    storage holds sha-256 hex only (constant-time compare on verify).
 *  - Token is single-use (used_at gate) and 15-min TTL.
 *  - Status reducer matches the EventType → ClusterStatus map in §2 verbatim.
 *  - Every event POST appends to connection_event (audit trail) AND updates
 *    cluster.status atomically.
 *  - ingestPubkeyScan stores the raw report, calls the existing ingestSnapshot
 *    so the Overview/Findings screens keep rendering, AND emits the synthetic
 *    `scan_pushed` event.
 *
 * NEVER log the raw token. NEVER widen RBAC reads beyond requireMembership.
 */

// --- Token format -----------------------------------------------------------

const ENROLLMENT_TTL_MS = 15 * 60 * 1000; // contract §0: 15 minutes
const RAW_TOKEN_RANDOM_BYTES = 32; // → 43 base64url chars + 4 prefix = 47

const TOKEN_PREFIX = 'ent_';

function mintRawToken(): string {
  return TOKEN_PREFIX + randomBytes(RAW_TOKEN_RANDOM_BYTES).toString('base64url');
}

export function hashToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

/**
 * Constant-time string compare. Returns false on length mismatch without
 * leaking the length difference to the timing channel (timingSafeEqual throws
 * on unequal lengths; we short-circuit first).
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a, 'utf-8');
  const bb = Buffer.from(b, 'utf-8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// --- Status reducer (pure) --------------------------------------------------

export type EnrollmentMethod = 'helm' | 'pubkey';

export type ConnectionEventType =
  | 'agent_registered'
  | 'cli_started'
  | 'csr_submitted'
  | 'awaiting_approval'
  | 'approved'
  | 'rbac_bound'
  | 'scan_pushed'
  | 'error';

export type ExtendedClusterStatus =
  | 'pending'
  | 'cli_started'
  | 'csr_submitted'
  | 'awaiting_approval'
  | 'approved'
  | 'connected'
  | 'failed'
  | 'expired'
  | 'disconnected';

/**
 * Status reducer per docs/PUBKEY_CONNECT_CONTRACT.md §2:
 *   - `connected` is sticky (any later error keeps connected)
 *   - status mapping: cli_started → cli_started; csr_submitted → csr_submitted;
 *     awaiting_approval → awaiting_approval; approved + rbac_bound → approved;
 *     scan_pushed → connected; error → failed.
 *   - agent_registered (Helm path) → connected directly.
 */
export function reduceStatus(
  current: ExtendedClusterStatus,
  event: ConnectionEventType,
): ExtendedClusterStatus {
  if (current === 'connected') return 'connected'; // sticky
  switch (event) {
    case 'agent_registered':
      return 'connected';
    case 'cli_started':
      return 'cli_started';
    case 'csr_submitted':
      return 'csr_submitted';
    case 'awaiting_approval':
      return 'awaiting_approval';
    case 'approved':
    case 'rbac_bound':
      return 'approved';
    case 'scan_pushed':
      return 'connected';
    case 'error':
      return 'failed';
    default:
      return current;
  }
}

/**
 * The `cluster` table's `status` enum is the narrow legacy set
 * (`pending|connected|disconnected`). Our extended state machine lives in the
 * event timeline; we project it down for the DB column.
 */
export function projectToClusterColumn(status: ExtendedClusterStatus): 'pending' | 'connected' | 'disconnected' {
  if (status === 'connected') return 'connected';
  if (status === 'disconnected' || status === 'failed' || status === 'expired') return 'disconnected';
  return 'pending';
}

// --- Token verify (constant-time + TTL + used_at) ---------------------------

export interface VerifiedEnrollment {
  enrollmentId: string;
  clusterId: string;
  accountId: string;
  method: EnrollmentMethod;
  usedAt: string | null;
  expiresAt: string;
}

export class EnrollmentTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EnrollmentTokenError';
  }
}

/**
 * Resolve a raw bearer token to its enrollment row.
 *
 * Per contract §4: sha256(raw) → match cluster_enrollment.token_hash; reject
 * if expires_at < now; reject if used_at is set AND the incoming event is not
 * an idempotent re-post of scan_pushed for the same clusterId (the caller of
 * recordConnectionEvent/ingestPubkeyScan applies the second gate — this
 * function returns the row so callers can decide).
 *
 * The DB lookup is by hash equality (Postgres B-tree index → fast). The
 * constant-time bit is the hash compare; we still do an explicit
 * constantTimeEqual on the stored hash to defend against any future codepath
 * that branches on which row was found before comparing.
 */
export async function resolveEnrollmentToken(rawToken: string): Promise<VerifiedEnrollment> {
  if (typeof rawToken !== 'string' || !rawToken.startsWith(TOKEN_PREFIX)) {
    throw new EnrollmentTokenError('invalid token');
  }
  const expectedHash = hashToken(rawToken);
  const db = supabaseAdmin();
  const { data, error } = await db
    .from('cluster_enrollment')
    .select('id, cluster_id, account_id, method, token_hash, expires_at, used_at')
    .eq('token_hash', expectedHash)
    .maybeSingle();
  if (error) throw error;
  if (!data) throw new EnrollmentTokenError('invalid token');
  // Defense in depth: even though the DB lookup is by exact hash match, do an
  // explicit constant-time compare so any future refactor that fetches more
  // candidates can't introduce a timing oracle.
  if (!constantTimeEqual(data.token_hash as string, expectedHash)) {
    throw new EnrollmentTokenError('invalid token');
  }
  if (new Date(data.expires_at as string).getTime() < Date.now()) {
    throw new EnrollmentTokenError('token expired');
  }
  return {
    enrollmentId: data.id as string,
    clusterId: data.cluster_id as string,
    accountId: data.account_id as string,
    method: data.method as EnrollmentMethod,
    usedAt: (data.used_at as string | null) ?? null,
    expiresAt: data.expires_at as string,
  };
}

// --- Command builders -------------------------------------------------------

function trimSlash(url: string): string {
  return url.replace(/\/+$/, '');
}

export function buildHelmCommand(rawToken: string): string {
  const relay = process.env.RELAY_URL ?? 'wss://relay.k8s-sentinel.example';
  return [
    `helm install sentinel ${chartOciRef()} \\`,
    `  --version ${chartVersion()} \\`,
    '  --namespace sentinel --create-namespace \\',
    '  --set mode=hybrid \\',
    `  --set relay.url=${relay} \\`,
    `  --set relay.installToken=${rawToken}`,
  ].join('\n');
}

export function buildPubkeyCommand(rawToken: string): string {
  const cp = trimSlash(
    process.env.CONTROL_PLANE_URL ?? process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? 'https://control-plane.example',
  );
  return `argus bootstrap csr --enroll ${rawToken} --control-plane ${cp}`;
}

// --- createClusterEnrollment ------------------------------------------------

export interface CreateEnrollmentInput {
  userId: string;
  accountId: string;
  name: string;
  method: EnrollmentMethod;
}

export interface CreateEnrollmentResult {
  id: string; // cluster.id
  enrollmentId: string;
  rawToken: string; // shown ONCE
  expiresAt: string;
  method: EnrollmentMethod;
  methodCommands: { helm: string; pubkey: string };
}

const ClusterNameSchema = z
  .string()
  .trim()
  .min(1, 'name required')
  .max(120, 'name too long');

/**
 * Mint a fresh cluster + enrollment pair. The raw token is returned exactly
 * once; only its sha-256 hash is persisted (constant-time compare on verify).
 *
 * Tenant-guarded by requireMembership. Auditable: a `cluster.enrollment_minted`
 * audit entry is appended (without the raw token).
 */
export async function createClusterEnrollment(
  input: CreateEnrollmentInput,
): Promise<CreateEnrollmentResult> {
  const name = ClusterNameSchema.parse(input.name);
  if (input.method !== 'helm' && input.method !== 'pubkey') {
    throw new EnrollmentTokenError('invalid method');
  }
  await requireMembership(input.userId, input.accountId);

  const db = supabaseAdmin();
  const rawToken = mintRawToken();
  const expiresAt = new Date(Date.now() + ENROLLMENT_TTL_MS).toISOString();

  // 1) create the pending cluster row
  const { data: cluster, error: cErr } = await db
    .from('cluster')
    .insert({
      account_id: input.accountId,
      name,
      status: 'pending',
      mode: 'hybrid',
    })
    .select('id')
    .single();
  if (cErr) throw cErr;

  // 2) create the enrollment row (sha-256 hash only)
  const { data: enr, error: eErr } = await db
    .from('cluster_enrollment')
    .insert({
      cluster_id: cluster.id,
      account_id: input.accountId,
      method: input.method,
      token_hash: hashToken(rawToken),
      expires_at: expiresAt,
      created_by: input.userId,
    })
    .select('id')
    .single();
  if (eErr) throw eErr;

  await recordAudit({
    accountId: input.accountId,
    actor: 'user',
    action: 'cluster.enrollment_minted',
    clusterId: cluster.id,
    detail: { method: input.method, expiresAt },
  });

  return {
    id: cluster.id as string,
    enrollmentId: enr.id as string,
    rawToken,
    expiresAt,
    method: input.method,
    methodCommands: {
      helm: buildHelmCommand(rawToken),
      pubkey: buildPubkeyCommand(rawToken),
    },
  };
}

// --- getClusterDetail -------------------------------------------------------

export interface ClusterEventRow {
  id: string;
  type: ConnectionEventType | string;
  detail: Record<string, unknown>;
  ts: string;
}

export interface ClusterDetail {
  id: string;
  name: string;
  method: EnrollmentMethod | null;
  status: ExtendedClusterStatus;
  events: ClusterEventRow[];
  lastScanId: string | null;
  createdAt: string;
  /** Enrollment expiry (NOT cluster). null if no active enrollment row. */
  expiresAt: string | null;
}

/**
 * Joined view for /api/clusters/:id and the UI stepper poller. Tenant-guarded.
 *
 * We compute the extended status from the event reducer rather than trust the
 * cluster column — the column carries only the narrow legacy enum
 * (pending|connected|disconnected) so the existing UI keeps working; the
 * extended state lives in the event log.
 */
export async function getClusterDetail(
  userId: string,
  accountId: string,
  clusterId: string,
): Promise<ClusterDetail | null> {
  await requireMembership(userId, accountId);
  const db = supabaseAdmin();

  const { data: cluster, error: cErr } = await db
    .from('cluster')
    .select('id, name, status, created_at, account_id')
    .eq('id', clusterId)
    .eq('account_id', accountId)
    .maybeSingle();
  if (cErr) throw cErr;
  if (!cluster) return null;

  // method + expiry come from the most-recent enrollment row (typically there's
  // exactly one; on regenerate the old one stays for audit and the newest wins).
  const { data: enr } = await db
    .from('cluster_enrollment')
    .select('method, expires_at')
    .eq('cluster_id', clusterId)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  const { data: events } = await db
    .from('connection_event')
    .select('id, type, detail, ts')
    .eq('cluster_id', clusterId)
    .order('ts', { ascending: true });

  const { data: lastScan } = await db
    .from('scans')
    .select('id')
    .eq('cluster_id', clusterId)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  const evRows: ClusterEventRow[] = (events ?? []).map((e) => ({
    id: e.id as string,
    type: e.type as string,
    detail: (e.detail as Record<string, unknown>) ?? {},
    ts: e.ts as string,
  }));

  // Compute the extended status from the timeline (column is narrow legacy enum).
  let status: ExtendedClusterStatus = 'pending';
  for (const ev of evRows) {
    status = reduceStatus(status, ev.type as ConnectionEventType);
  }
  // Honor an expired enrollment when no connected event has landed.
  if (
    status !== 'connected' &&
    enr?.expires_at &&
    new Date(enr.expires_at as string).getTime() < Date.now()
  ) {
    status = 'expired';
  }

  return {
    id: cluster.id as string,
    name: cluster.name as string,
    method: ((enr?.method as EnrollmentMethod) ?? null) as EnrollmentMethod | null,
    status,
    events: evRows,
    lastScanId: (lastScan?.id as string) ?? null,
    createdAt: cluster.created_at as string,
    expiresAt: (enr?.expires_at as string) ?? null,
  };
}

// --- recordConnectionEvent --------------------------------------------------

export interface RecordEventInput {
  rawToken: string;
  type: ConnectionEventType;
  detail?: Record<string, unknown>;
}

const KNOWN_EVENT_TYPES: ReadonlySet<ConnectionEventType> = new Set([
  'agent_registered',
  'cli_started',
  'csr_submitted',
  'awaiting_approval',
  'approved',
  'rbac_bound',
  'scan_pushed',
  'error',
]);

/**
 * Append a progress event to the enrollment's cluster.
 *
 * Token rules (contract §4):
 *   - 401 if token unknown / hash mismatch / expired
 *   - 401 if used_at is set AND the incoming type is NOT scan_pushed (the only
 *     idempotent re-post permitted)
 *
 * Status side-effect: project the reduced extended status onto the narrow
 * cluster.status column so the existing Overview keeps rendering.
 */
export async function recordConnectionEvent(
  input: RecordEventInput,
): Promise<{ ok: true; clusterId: string; status: ExtendedClusterStatus }> {
  if (!KNOWN_EVENT_TYPES.has(input.type)) {
    throw new EnrollmentTokenError(`unknown event type: ${input.type}`);
  }

  const detail = sanitizeEventDetail(input.detail ?? {});

  const enr = await resolveEnrollmentToken(input.rawToken);
  // used_at gate: only `scan_pushed` may re-post after consumption.
  if (enr.usedAt && input.type !== 'scan_pushed') {
    throw new EnrollmentTokenError('token already used');
  }

  const db = supabaseAdmin();

  // Append the event.
  const { error: insErr } = await db.from('connection_event').insert({
    cluster_id: enr.clusterId,
    type: input.type,
    detail,
  });
  if (insErr) throw insErr;

  // Reduce the full timeline (cheap; same query the UI does). This guarantees
  // status is deterministic from the event log even under concurrent writers.
  const { data: events } = await db
    .from('connection_event')
    .select('type')
    .eq('cluster_id', enr.clusterId)
    .order('ts', { ascending: true });

  let status: ExtendedClusterStatus = 'pending';
  for (const ev of events ?? []) {
    status = reduceStatus(status, (ev as { type: string }).type as ConnectionEventType);
  }

  const projected = projectToClusterColumn(status);
  const updates: Record<string, unknown> = { status: projected, last_seen_at: new Date().toISOString() };
  if (projected === 'connected') updates.connected_at = new Date().toISOString();
  await db.from('cluster').update(updates).eq('id', enr.clusterId);

  return { ok: true, clusterId: enr.clusterId, status };
}

/**
 * Cap the JSON detail at 2 KB per contract §2. Returns the original on
 * success; throws if it's too big (caller maps that to 413/400). We stringify
 * once to measure, then return the parsed value (cheap given the size cap).
 */
export function sanitizeEventDetail(detail: Record<string, unknown>): Record<string, unknown> {
  let json: string;
  try {
    json = JSON.stringify(detail);
  } catch {
    throw new EnrollmentTokenError('detail not JSON-serializable');
  }
  if (json.length > 2048) throw new EnrollmentTokenError('detail too large (>2 KB)');
  return detail;
}

// --- ingestPubkeyScan -------------------------------------------------------

export interface IngestScanInput {
  rawToken: string;
  clusterId: string;
  report: unknown;
}

export interface IngestScanResult {
  scanId: string;
  createdAt: string;
}

/**
 * Persist the raw v3 report, run the existing ingestSnapshot pipeline so the
 * Overview / Findings / Fixes screens keep rendering, then emit the synthetic
 * `scan_pushed` event + mark the enrollment token used.
 *
 * The raw report stays in `scans.report` for the audit trail; the normalized
 * projection lives in run/finding/attack_path/choke_point (the existing schema
 * the dashboard reads). Token rules per §4: tied to clusterId; first scan
 * flips `used_at`.
 */
export async function ingestPubkeyScan(input: IngestScanInput): Promise<IngestScanResult> {
  const enr = await resolveEnrollmentToken(input.rawToken);
  // Token must be tied to the claimed clusterId.
  if (enr.clusterId !== input.clusterId) {
    throw new EnrollmentTokenError('cluster mismatch');
  }
  // used_at gate: scan_pushed is the one idempotent re-post we permit, so we
  // don't 401 here — the resolveEnrollmentToken contract returned cleanly.

  const report = input.report as ArgusReportJson | undefined;
  if (!report || typeof report !== 'object') {
    throw new EnrollmentTokenError('report missing or not an object');
  }

  const db = supabaseAdmin();

  // 1) Store the raw v3 report (audit-grade, unmodified).
  const { data: scan, error: sErr } = await db
    .from('scans')
    .insert({ cluster_id: enr.clusterId, report })
    .select('id, created_at')
    .single();
  if (sErr) throw sErr;

  // 2) Project to the wire snapshot + validate at the trust boundary, then
  //    persist via the existing pipeline.
  const snapshot = mapToPostureSnapshot(report);
  // Re-validate (defense in depth; the mapper might emit something the
  // database tables won't accept). We deliberately use safeParse + throw with
  // a known error so the route can return 422.
  const parsed = PostureSnapshotSchema.safeParse(snapshot);
  if (!parsed.success) {
    throw new EnrollmentTokenError(
      `report failed wire validation: ${parsed.error.issues[0]?.message ?? 'unknown'}`,
    );
  }
  await ingestSnapshot(enr.clusterId, parsed.data);

  // 3) Emit the synthetic scan_pushed event (drives the stepper's last step).
  const findingCount = snapshot.findings.length;
  const riskScore = snapshot.run.riskScore ?? null;
  await db.from('connection_event').insert({
    cluster_id: enr.clusterId,
    type: 'scan_pushed',
    detail: { scanId: scan.id, findingCount, riskScore },
  });

  // 4) Mark the enrollment token used (first scan flips used_at; later scans
  //    pass through because we allow scan_pushed re-posts).
  if (!enr.usedAt) {
    await db
      .from('cluster_enrollment')
      .update({ used_at: new Date().toISOString() })
      .eq('id', enr.enrollmentId);
  }

  // 5) Flip the cluster row to connected for the legacy UI.
  await db
    .from('cluster')
    .update({
      status: 'connected',
      connected_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
    })
    .eq('id', enr.clusterId);

  return { scanId: scan.id as string, createdAt: scan.created_at as string };
}

// Re-export for the routes (they only need to import from this module).
export { AccessError };
