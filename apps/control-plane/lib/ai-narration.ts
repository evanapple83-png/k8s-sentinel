import 'server-only';
import { createHash } from 'node:crypto';
import { supabaseAdmin } from './supabase/server';

/**
 * AI narration layer — shared core for the four /api/ai/* endpoints.
 *
 * Build-step 1 of docs/AI_NARRATION_SPEC.md is this file plus a thin route
 * handler. The model NEVER replaces the deterministic v3 engine; it explains
 * and converses over the report the engine already produced. The provided
 * report.json is the model's sole source of truth.
 *
 * Architecture (non-negotiable, spec §1):
 *   - API key stays server-side (process.env.ANTHROPIC_API_KEY).
 *   - The browser → /api/ai/* → this lib → Anthropic. Anthropic is hit with
 *     the CVP-verified org's key only; the dashboard never sees a key.
 *   - Default model claude-sonnet-4-6 (configurable per endpoint via
 *     AI_NARRATION_MODEL env or callsite override).
 *   - Calls are stateless: each request reloads the latest scan for the
 *     active cluster and builds a fresh prompt.
 *
 * Caching strategy (verified against shared/prompt-caching.md):
 *   - System prompt (~600 tokens, fixed) ALONE is below Sonnet 4.6's
 *     2048-token cacheable minimum, so caching it standalone silently fails.
 *   - We combine the system prompt + the v3 report.json into the same
 *     `system` array and put the cache breakpoint on the report block. The
 *     full system prefix (system prompt + report) is cached per
 *     (clusterId, scanId, model); the per-finding user turn varies per
 *     request and is uncached.
 *   - Auditing surfaces `cache_read_input_tokens` so we can verify hit rate.
 *     If it's zero across repeated requests for the same scan, a silent
 *     invalidator landed (timestamp in system, non-deterministic JSON, etc.).
 *
 * Safety (spec §2 + §6):
 *   - Defensive system prompt enforces: no exploit code / payloads, no
 *     mutating commands, cite only IDs present in the report or say so.
 *   - Hallucination post-check parses citations and appends a soft warning
 *     when the model references a finding/path/jewel not in the report.
 *   - Every call writes one ai_audit row (account, user, cluster, scan,
 *     endpoint, prompt hash, token counts, output, citation-warning flag).
 *   - Rate limit + cost cap enforced on the way in (return 429 + Retry-After
 *     on either trip).
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export type NarrationEndpoint = 'explain-finding' | 'explain-path' | 'explain-fix' | 'ask';

export interface ExplainFindingInput {
  /** Tenant-scoped — caller must already have verified membership of accountId. */
  accountId: string;
  /** Signed-in user (for audit + per-user rate limit). */
  userId: string;
  /** The cluster the finding belongs to. Must be in accountId. */
  clusterId: string;
  /** Engine-emitted finding id (e.g. 'trivy-001'). */
  findingId: string;
  /** Optional model override (defaults to AI_NARRATION_MODEL env or claude-sonnet-4-6). */
  modelOverride?: string;
  /** Inject a fetch impl for tests; defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export interface Citation {
  type: 'finding' | 'path' | 'chokepoint' | 'jewel';
  id: string;
}

export interface NarrationResponse {
  explanation: string;
  citations: Citation[];
  /** True when post-check found the model referenced something not in the report. */
  citationWarning: boolean;
  model: string;
  usage: {
    inputTokens: number;
    outputTokens: number;
    cacheCreationInputTokens: number;
    cacheReadInputTokens: number;
  };
}

// ---------------------------------------------------------------------------
// Error classes — let the route map cleanly to HTTP codes.
// ---------------------------------------------------------------------------

export class AiNarrationError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly cause?: unknown,
  ) {
    super(message);
    this.name = 'AiNarrationError';
  }
}

export class RateLimitError extends AiNarrationError {
  constructor(public readonly retryAfterSeconds: number, message: string) {
    super(429, message);
    this.name = 'RateLimitError';
  }
}

export class CostCapError extends AiNarrationError {
  constructor(message: string) {
    super(429, message);
    this.name = 'CostCapError';
  }
}

// ---------------------------------------------------------------------------
// Defensive system prompt (spec §2, verbatim aside from formatting).
// Keep this BYTE-STABLE — every change invalidates every cached prefix.
// ---------------------------------------------------------------------------

export const SYSTEM_PROMPT = `You are the security analyst inside K8s Sentinel. You explain Kubernetes posture findings to a smart non-expert.

The provided cluster scan report (JSON) is your sole source of truth. Only cite findings, paths, choke points, and assets that appear in it; reference findings by ID (e.g., F-001 or the exact id used in the report), paths by their target, and choke points by their fix description. If the report does not contain enough to answer, say so — do not invent.

You may explain exploitability, reachability, and attack-path reasoning in defensive language. You may NOT generate exploit code, payloads, offensive tooling, or step-by-step attack instructions. You may NOT propose commands that modify the cluster — remediations are described conceptually (patch X, drop privileged on Y, remove RBAC verb Z) and handed to the user, never executed.

Be concise. Use SSVC vocabulary (Act / Attend / Track / Track*) where it helps. When something is uncertain (e.g., reachability inferred from an absent NetworkPolicy), say so explicitly.`;

// ---------------------------------------------------------------------------
// Pricing (USD per 1M tokens — kept in micro-cents to do integer math).
// Sonnet 4.6 base price from claude-api skill cached table 2026-04-29:
//   $3.00 input / $15.00 output per 1M tokens.
//   Cache write: 1.25× input. Cache read: 0.1× input.
// ---------------------------------------------------------------------------

interface ModelPrice {
  /** USD micro-cents per million input tokens. $3 = 300_000_000. */
  inputPerMillion: number;
  outputPerMillion: number;
  /** Cache-write multiplier on the input price (5-min TTL default). */
  cacheWriteMultiplier: number;
  /** Cache-read multiplier on the input price. */
  cacheReadMultiplier: number;
}

const PRICES: Record<string, ModelPrice> = {
  'claude-sonnet-4-6': {
    inputPerMillion: 3_000_000,
    outputPerMillion: 15_000_000,
    cacheWriteMultiplier: 1.25,
    cacheReadMultiplier: 0.1,
  },
  'claude-opus-4-7': {
    inputPerMillion: 5_000_000,
    outputPerMillion: 25_000_000,
    cacheWriteMultiplier: 1.25,
    cacheReadMultiplier: 0.1,
  },
  'claude-haiku-4-5': {
    inputPerMillion: 1_000_000,
    outputPerMillion: 5_000_000,
    cacheWriteMultiplier: 1.25,
    cacheReadMultiplier: 0.1,
  },
};

export function costMicroCents(
  model: string,
  usage: { inputTokens: number; outputTokens: number; cacheCreationInputTokens: number; cacheReadInputTokens: number },
): number {
  const p = PRICES[model] ?? PRICES['claude-sonnet-4-6']!;
  // Round half-up to integer micro-cents per category, then sum. Drift over a
  // million calls is sub-cent; matches what the Anthropic invoice rounds to.
  const uncachedInput = (usage.inputTokens * p.inputPerMillion) / 1_000_000;
  const cacheWrite = (usage.cacheCreationInputTokens * p.inputPerMillion * p.cacheWriteMultiplier) / 1_000_000;
  const cacheRead = (usage.cacheReadInputTokens * p.inputPerMillion * p.cacheReadMultiplier) / 1_000_000;
  const output = (usage.outputTokens * p.outputPerMillion) / 1_000_000;
  return Math.round(uncachedInput + cacheWrite + cacheRead + output);
}

// ---------------------------------------------------------------------------
// Rate-limit + cost cap config (spec §6). Configurable via env, with the
// defaults the spec recommends.
// ---------------------------------------------------------------------------

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export const RATE_LIMITS = {
  perUserPerMinute: intEnv('AI_NARRATION_USER_RPM', 30),
  perAccountPerDay: intEnv('AI_NARRATION_ACCOUNT_DAILY', 500),
  /** USD micro-cents. Default $10.00/month per workspace. */
  perAccountMonthlyCostMicroCents: intEnv('AI_NARRATION_ACCOUNT_MONTHLY_USD_CENTS', 10_00) * 10_000,
};

// ---------------------------------------------------------------------------
// Anthropic API client — raw fetch (spec §1 + user directive: minimal deps).
// ---------------------------------------------------------------------------

interface AnthropicMessage {
  role: 'user' | 'assistant';
  content: string;
}

interface AnthropicSystemBlock {
  type: 'text';
  text: string;
  cache_control?: { type: 'ephemeral' };
}

interface AnthropicResponse {
  id: string;
  type: 'message';
  role: 'assistant';
  content: Array<{ type: 'text'; text: string } | { type: string }>;
  model: string;
  stop_reason: string | null;
  usage: {
    input_tokens: number;
    output_tokens: number;
    cache_creation_input_tokens?: number;
    cache_read_input_tokens?: number;
  };
}

interface CallClaudeOptions {
  apiKey: string;
  model: string;
  systemBlocks: AnthropicSystemBlock[];
  messages: AnthropicMessage[];
  maxTokens: number;
  fetchImpl: typeof fetch;
}

/**
 * Single-shot call to /v1/messages. Returns the full response; never streams
 * (spec §1 says streaming is for ask only). Maps Anthropic HTTP errors into
 * AiNarrationError so the route handler doesn't have to peek inside.
 */
export async function callClaude(opts: CallClaudeOptions): Promise<AnthropicResponse> {
  let resp: Response;
  try {
    resp = await opts.fetchImpl('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-api-key': opts.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: opts.model,
        max_tokens: opts.maxTokens,
        system: opts.systemBlocks,
        messages: opts.messages,
      }),
    });
  } catch (err) {
    throw new AiNarrationError(502, 'Anthropic API unreachable', err);
  }

  if (resp.status === 429) {
    const retryAfter = Number.parseInt(resp.headers.get('retry-after') ?? '60', 10);
    throw new RateLimitError(
      Number.isFinite(retryAfter) ? retryAfter : 60,
      'Anthropic upstream rate limit reached',
    );
  }
  if (resp.status === 529) {
    throw new AiNarrationError(503, 'Anthropic API overloaded — retry shortly');
  }
  if (resp.status === 401 || resp.status === 403) {
    throw new AiNarrationError(503, 'Anthropic API key invalid or lacks model access');
  }
  if (resp.status >= 400) {
    const body = await resp.text().catch(() => '');
    throw new AiNarrationError(502, `Anthropic API error ${resp.status}: ${body.slice(0, 400)}`);
  }

  let json: AnthropicResponse;
  try {
    json = (await resp.json()) as AnthropicResponse;
  } catch (err) {
    throw new AiNarrationError(502, 'Anthropic API returned non-JSON', err);
  }
  if (!json || json.type !== 'message' || !Array.isArray(json.content)) {
    throw new AiNarrationError(502, 'Anthropic API response missing message content');
  }
  return json;
}

/** Concatenate every `text` block in the response. Other block types are ignored. */
export function extractText(resp: AnthropicResponse): string {
  return resp.content
    .filter((b): b is { type: 'text'; text: string } => b.type === 'text' && typeof (b as { text?: unknown }).text === 'string')
    .map((b) => b.text)
    .join('');
}

// ---------------------------------------------------------------------------
// Report trimming + deterministic serialization (caching invariant: same
// bytes every request for the same scan).
// ---------------------------------------------------------------------------

interface RawReport {
  cluster?: string;
  scannedAt?: string;
  riskScore?: number;
  intel?: { source?: string; version?: string; kev_count?: number };
  reachableJewels?: unknown[];
  paths?: Record<string, unknown>;
  chokePoints?: unknown[];
  findings?: Array<Record<string, unknown>>;
  [k: string]: unknown;
}

/**
 * For explain-finding: pass the top-level intel + reachableJewels + paths +
 * chokePoints, plus ONLY the targeted finding from `findings[]`. Drops
 * activeFindings / workloads / acceptedRisks / refusals / metadata (big and
 * irrelevant for one-finding context). Stays well under the cache window
 * while preserving the engine's structural signals.
 */
export function buildFindingContext(report: RawReport, findingId: string): {
  context: RawReport;
  found: boolean;
} {
  const all = Array.isArray(report.findings) ? report.findings : [];
  const target = all.find((f) => typeof f === 'object' && f && (f as { id?: unknown }).id === findingId);
  if (!target) {
    return { context: { cluster: report.cluster, scannedAt: report.scannedAt }, found: false };
  }
  return {
    context: {
      cluster: report.cluster,
      scannedAt: report.scannedAt,
      riskScore: report.riskScore,
      intel: report.intel,
      reachableJewels: report.reachableJewels,
      paths: report.paths,
      chokePoints: report.chokePoints,
      // Only one finding — enough for the model to explain it in cluster context.
      findings: [target],
    },
    found: true,
  };
}

/**
 * Deterministic JSON serialization — sorts object keys at every level so the
 * cached prefix doesn't drift between Node versions / JSON impls.
 */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys
    .map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`)
    .join(',')}}`;
}

// ---------------------------------------------------------------------------
// Hallucination post-check (spec §7).
// ---------------------------------------------------------------------------

/** Crude but reliable: pull every <ws>finding-id-style<ws> token from the prose. */
export function extractCitations(text: string, report: RawReport): {
  citations: Citation[];
  warnings: string[];
} {
  const citations: Citation[] = [];
  const warnings: string[] = [];

  const findings = Array.isArray(report.findings) ? report.findings : [];
  const knownFindingIds = new Set(
    findings
      .map((f) => (f && typeof f === 'object' ? (f as { id?: unknown }).id : null))
      .filter((id): id is string => typeof id === 'string'),
  );
  const knownJewels = new Set(
    (Array.isArray(report.reachableJewels) ? report.reachableJewels : [])
      .filter((j): j is string => typeof j === 'string'),
  );
  const knownPaths = new Set(Object.keys(report.paths ?? {}));

  // Tokens that look like an engine id: alnum + - / : (e.g. trivy-001, F-001,
  // secret:payments/db-credentials, CLUSTER-ADMIN). Bounded length to skip
  // prose like "the-attacker-could".
  const tokenRe = /[A-Za-z][A-Za-z0-9\-:\/_]{2,128}/g;
  const seen = new Set<string>();
  for (const raw of text.matchAll(tokenRe)) {
    const tok = raw[0];
    if (seen.has(tok)) continue;
    seen.add(tok);

    if (knownFindingIds.has(tok)) {
      citations.push({ type: 'finding', id: tok });
      continue;
    }
    // Path targets and crown jewels overlap by construction in v3 output —
    // `paths` is keyed BY the jewel string. Check path first so the more
    // contextual label wins when the engine emits the same string in both
    // sets; this matches how the model is asked to cite ("paths by their
    // target", spec §2).
    if (knownPaths.has(tok)) {
      citations.push({ type: 'path', id: tok });
      continue;
    }
    if (knownJewels.has(tok)) {
      citations.push({ type: 'jewel', id: tok });
      continue;
    }
    // Looks like a finding id shape (alnum-with-dashes containing a digit
    // run) but isn't in the report → likely an invented citation. Skip
    // obvious false positives (CVE-2026-… etc. are fine to mention without
    // being in `findings[]` — they're in the report body).
    if (/^[A-Z]+-\d{3,}$/i.test(tok) && !tok.toUpperCase().startsWith('CVE-')) {
      warnings.push(tok);
    }
  }

  return { citations, warnings };
}

// ---------------------------------------------------------------------------
// Rate limit + cost cap (DB-backed buckets — spec §6).
// ---------------------------------------------------------------------------

function minuteStart(d: Date): string {
  const x = new Date(d);
  x.setUTCSeconds(0, 0);
  return x.toISOString();
}
function dayStart(d: Date): string {
  const x = new Date(d);
  x.setUTCHours(0, 0, 0, 0);
  return x.toISOString();
}
function monthStart(d: Date): string {
  const x = new Date(d);
  x.setUTCDate(1);
  x.setUTCHours(0, 0, 0, 0);
  return x.toISOString();
}

/**
 * Pre-flight: assert the caller is under the per-user/min and per-account/day
 * limits AND the monthly cost cap (estimated against a worst-case spend).
 * Throws RateLimitError / CostCapError on rejection; returns silently on pass.
 *
 * Worst-case cost estimate is intentionally generous — we don't know token
 * counts before the call, so we assume the prompt landed uncached. After the
 * call we record the true spend.
 */
export async function checkAndReserveRateLimit(input: {
  accountId: string;
  userId: string;
  model: string;
  now?: Date;
}): Promise<void> {
  const db = supabaseAdmin();
  const now = input.now ?? new Date();
  const userMin = minuteStart(now);
  const accDay = dayStart(now);
  const accMon = monthStart(now);

  // Use parallel select-then-decide to keep the function cheap. We're not
  // racing against ourselves (the audit row written after the call uses an
  // independent INSERT), so we tolerate brief over-count under heavy
  // concurrency rather than wrapping in a transaction.
  const [minRow, dayRow, monthRow] = await Promise.all([
    db
      .from('ai_rate_window')
      .select('count, cost_microcents')
      .eq('bucket_kind', 'user_minute')
      .eq('subject_id', input.userId)
      .eq('bucket_start', userMin)
      .maybeSingle(),
    db
      .from('ai_rate_window')
      .select('count, cost_microcents')
      .eq('bucket_kind', 'account_day')
      .eq('subject_id', input.accountId)
      .eq('bucket_start', accDay)
      .maybeSingle(),
    db
      .from('ai_rate_window')
      .select('count, cost_microcents')
      .eq('bucket_kind', 'account_month_cost')
      .eq('subject_id', input.accountId)
      .eq('bucket_start', accMon)
      .maybeSingle(),
  ]);

  const userMinCount = (minRow.data?.count as number | undefined) ?? 0;
  if (userMinCount >= RATE_LIMITS.perUserPerMinute) {
    throw new RateLimitError(
      60,
      `Per-user rate limit reached (${RATE_LIMITS.perUserPerMinute}/min). Try again in a minute.`,
    );
  }
  const accDayCount = (dayRow.data?.count as number | undefined) ?? 0;
  if (accDayCount >= RATE_LIMITS.perAccountPerDay) {
    throw new RateLimitError(
      // Until the day rolls over; cap at 1h hint so clients don't hammer.
      3600,
      `Workspace daily limit reached (${RATE_LIMITS.perAccountPerDay}/day). Resets at UTC midnight.`,
    );
  }
  const accMonCost = Number((monthRow.data?.cost_microcents as number | undefined) ?? 0);
  if (accMonCost >= RATE_LIMITS.perAccountMonthlyCostMicroCents) {
    throw new CostCapError(
      `Workspace monthly AI cost cap reached ($${(RATE_LIMITS.perAccountMonthlyCostMicroCents / 1_000_000).toFixed(2)}). Raise the cap in settings or wait for month rollover.`,
    );
  }
}

/** Increment the three buckets + add the post-call cost. Fire-and-forget. */
export async function recordUsage(input: {
  accountId: string;
  userId: string;
  costMicroCents: number;
  now?: Date;
}): Promise<void> {
  const db = supabaseAdmin();
  const now = input.now ?? new Date();
  const upserts = [
    {
      bucket_kind: 'user_minute',
      subject_id: input.userId,
      bucket_start: minuteStart(now),
    },
    {
      bucket_kind: 'account_day',
      subject_id: input.accountId,
      bucket_start: dayStart(now),
    },
    {
      bucket_kind: 'account_month_cost',
      subject_id: input.accountId,
      bucket_start: monthStart(now),
    },
  ];
  await Promise.all(
    upserts.map(async (u) => {
      const { data } = await db
        .from('ai_rate_window')
        .select('count, cost_microcents')
        .eq('bucket_kind', u.bucket_kind)
        .eq('subject_id', u.subject_id)
        .eq('bucket_start', u.bucket_start)
        .maybeSingle();
      const prevCount = (data?.count as number | undefined) ?? 0;
      const prevCost = Number((data?.cost_microcents as number | undefined) ?? 0);
      const addCost = u.bucket_kind === 'account_month_cost' ? input.costMicroCents : 0;
      await db.from('ai_rate_window').upsert(
        {
          bucket_kind: u.bucket_kind,
          subject_id: u.subject_id,
          bucket_start: u.bucket_start,
          count: prevCount + 1,
          cost_microcents: prevCost + addCost,
          updated_at: now.toISOString(),
        },
        { onConflict: 'bucket_kind,subject_id,bucket_start' },
      );
    }),
  );
}

// ---------------------------------------------------------------------------
// Audit-log row
// ---------------------------------------------------------------------------

interface WriteAuditInput {
  accountId: string;
  userId: string;
  clusterId: string;
  scanId: string | null;
  endpoint: NarrationEndpoint;
  model: string;
  targetKind: 'finding' | 'path' | 'fix' | 'ask';
  targetId: string;
  promptHash: string;
  status: 'ok' | 'refused' | 'error' | 'rate_limited' | 'cost_capped';
  usage: NarrationResponse['usage'];
  costMicroCents: number;
  outputText: string;
  hasCitationWarning: boolean;
  errorMessage?: string;
}

export async function writeAudit(input: WriteAuditInput): Promise<void> {
  const db = supabaseAdmin();
  const { error } = await db.from('ai_audit').insert({
    account_id: input.accountId,
    user_id: input.userId,
    cluster_id: input.clusterId,
    scan_id: input.scanId,
    endpoint: input.endpoint,
    model: input.model,
    target_kind: input.targetKind,
    target_id: input.targetId,
    prompt_hash: input.promptHash,
    input_tokens: input.usage.inputTokens,
    output_tokens: input.usage.outputTokens,
    cache_creation_input_tokens: input.usage.cacheCreationInputTokens,
    cache_read_input_tokens: input.usage.cacheReadInputTokens,
    cost_microcents: input.costMicroCents,
    status: input.status,
    error_message: input.errorMessage ?? null,
    // Cap stored text at 16 KB; if longer, dashboard can re-query Anthropic.
    output_text: input.outputText.slice(0, 16_000),
    has_citation_warning: input.hasCitationWarning,
  });
  if (error) {
    // Don't block the user response on an audit-write failure — log + carry on.
    console.error('[ai-audit] insert failed:', error);
  }
}

// ---------------------------------------------------------------------------
// Latest scan lookup — load the v3 report for a cluster.
// ---------------------------------------------------------------------------

export async function loadLatestScanReport(clusterId: string): Promise<{
  scanId: string;
  report: RawReport;
} | null> {
  const db = supabaseAdmin();
  // Tenant scope is enforced by the route's requireMembership before this
  // function is called. Here we just take the cluster id at face value.
  const { data, error } = await db
    .from('scans')
    .select('id, report')
    .eq('cluster_id', clusterId)
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) throw error;
  if (!data) return null;
  return { scanId: data.id as string, report: data.report as RawReport };
}

// ---------------------------------------------------------------------------
// THE endpoint: explain a single finding.
// ---------------------------------------------------------------------------

/**
 * Wire the whole flow:
 *   1. Verify ANTHROPIC_API_KEY is set (503 if not).
 *   2. Pre-flight rate + cost cap.
 *   3. Load latest scan; if no scan, 404.
 *   4. Build trimmed context for the finding; if id missing, 422.
 *   5. Build prompt with the system/report cache breakpoint.
 *   6. Call Claude.
 *   7. Post-check citations; compute cost; record usage; write audit.
 *
 * Caller (the route) handles HTTP shaping — this function throws typed errors.
 */
export async function explainFinding(input: ExplainFindingInput): Promise<NarrationResponse> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new AiNarrationError(503, 'AI narration not configured: missing ANTHROPIC_API_KEY');
  }
  const model = input.modelOverride ?? process.env.AI_NARRATION_MODEL ?? 'claude-sonnet-4-6';

  // 1. Rate + cost cap. Rejecting BEFORE the Anthropic call protects spend.
  await checkAndReserveRateLimit({ accountId: input.accountId, userId: input.userId, model });

  // 2. Latest scan.
  const latest = await loadLatestScanReport(input.clusterId);
  if (!latest) {
    throw new AiNarrationError(404, 'No scan found for this cluster yet — run one before asking for an explanation');
  }
  const { scanId, report } = latest;

  // 3. Trim context to the targeted finding + structural top-level. If the
  // finding id isn't in this scan, refuse outright — saves an Anthropic call
  // and an audit "model invented an ID" follow-up.
  const { context, found } = buildFindingContext(report, input.findingId);
  if (!found) {
    throw new AiNarrationError(
      422,
      `Finding ${input.findingId} is not in the latest scan for this cluster. (It may have closed, or you may be looking at a stale tab.)`,
    );
  }

  // 4. Build the prompt. System prompt + report context are cached together;
  //    only the user turn varies per request.
  const reportJson = stableStringify(context);
  const userMessage = [
    `Explain finding ${input.findingId} in plain English for a smart non-expert.`,
    'Cover: what the issue is, why it matters on THIS workload (cite the relevant attack-path step or chokepoint if any), and what the recommended action is.',
    'Keep it to 4-8 sentences. Cite finding ids and path targets verbatim from the report.',
  ].join(' ');
  const systemBlocks: AnthropicSystemBlock[] = [
    { type: 'text', text: SYSTEM_PROMPT },
    {
      type: 'text',
      text: `Latest scan report (JSON) for cluster ${context.cluster ?? input.clusterId}:\n\n${reportJson}`,
      cache_control: { type: 'ephemeral' },
    },
  ];
  const messages: AnthropicMessage[] = [{ role: 'user', content: userMessage }];

  const promptHash = createHash('sha256')
    .update(SYSTEM_PROMPT)
    .update('\n--\n')
    .update(reportJson)
    .update('\n--\n')
    .update(userMessage)
    .digest('hex');

  // 5. Call Claude.
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  let upstream;
  try {
    upstream = await callClaude({
      apiKey,
      model,
      systemBlocks,
      messages,
      maxTokens: 1024,
      fetchImpl,
    });
  } catch (err) {
    await writeAudit({
      accountId: input.accountId,
      userId: input.userId,
      clusterId: input.clusterId,
      scanId,
      endpoint: 'explain-finding',
      model,
      targetKind: 'finding',
      targetId: input.findingId,
      promptHash,
      status: 'error',
      usage: { inputTokens: 0, outputTokens: 0, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 },
      costMicroCents: 0,
      outputText: '',
      hasCitationWarning: false,
      errorMessage: err instanceof Error ? err.message : String(err),
    }).catch(() => undefined);
    throw err;
  }

  // 6. Extract + post-check.
  const explanation = extractText(upstream).trim();
  const { citations, warnings } = extractCitations(explanation, report);
  const hasCitationWarning = warnings.length > 0;
  const finalExplanation = hasCitationWarning
    ? `${explanation}\n\n_Note: this response referenced item${warnings.length === 1 ? '' : 's'} not in the current scan (${warnings.slice(0, 3).join(', ')})._`
    : explanation;

  const usage: NarrationResponse['usage'] = {
    inputTokens: upstream.usage.input_tokens ?? 0,
    outputTokens: upstream.usage.output_tokens ?? 0,
    cacheCreationInputTokens: upstream.usage.cache_creation_input_tokens ?? 0,
    cacheReadInputTokens: upstream.usage.cache_read_input_tokens ?? 0,
  };
  const cost = costMicroCents(model, usage);

  // 7. Record + audit. Done in parallel — neither blocks the response.
  await Promise.all([
    recordUsage({ accountId: input.accountId, userId: input.userId, costMicroCents: cost }).catch((e) =>
      console.error('[ai-narration] recordUsage failed:', e),
    ),
    writeAudit({
      accountId: input.accountId,
      userId: input.userId,
      clusterId: input.clusterId,
      scanId,
      endpoint: 'explain-finding',
      model,
      targetKind: 'finding',
      targetId: input.findingId,
      promptHash,
      status: upstream.stop_reason === 'refusal' ? 'refused' : 'ok',
      usage,
      costMicroCents: cost,
      outputText: finalExplanation,
      hasCitationWarning,
    }).catch((e) => console.error('[ai-narration] writeAudit failed:', e)),
  ]);

  return {
    explanation: finalExplanation,
    citations,
    citationWarning: hasCitationWarning,
    model,
    usage,
  };
}
