import { z } from 'zod';

/**
 * Relay wire protocol (Phase 5, hybrid mode — BUILD.md §hybrid, docs/DATA-BOUNDARY.md).
 *
 * The contract between the in-cluster **agent** (apps/api, dials out) and the
 * hosted **control plane** (apps/control-plane), brokered by the stateless
 * **relay** (apps/relay). It is deliberately self-contained (zod only): it is a
 * TRUST BOUNDARY, so every byte the agent sends up is structurally validated and
 * size-capped here before any hosted code touches it. The agent maps its
 * internal (core) types onto these wire shapes; the control plane maps them onto
 * its own. Neither side shares a type with the other — the wire is the contract.
 *
 * Transport-agnostic: logic runs over the injectable {@link Transport} (string
 * frames in/out). The production adapter wraps a WebSocket; tests use
 * {@link createMemoryTransportPair}. This mirrors how engine-hermes injects
 * `fetch` so the whole stack is exercised offline.
 */

export const PROTOCOL_VERSION = 1;

/** Hard ceiling on a single decoded frame (defense against a flooding peer). */
export const MAX_FRAME_BYTES = 8 * 1024 * 1024; // 8 MiB

// --- Posture wire shapes (the "leaves the cluster" set, DATA-BOUNDARY.md) ----
// Mirrors apps/control-plane/lib/types.ts field-for-field so hosted ingest is a
// near 1:1 map. Every string is length-capped and every array is bounded.

const Str = (max = 4096) => z.string().max(max);
const ShortStr = (max = 256) => z.string().max(max);

export const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low', 'info']);

export const ResourceRefSchema = z.object({
  kind: ShortStr(),
  name: ShortStr(),
  namespace: ShortStr().optional(),
  image: ShortStr(512).optional(),
  path: ShortStr(1024).optional(),
});

export const ControlRefSchema = z.object({
  framework: ShortStr(),
  id: ShortStr(),
  title: ShortStr().optional(),
});

/**
 * SSVC (Stakeholder-Specific Vulnerability Categorization) decision — emitted
 * by the v3 attack-graph engine. ``Act`` = exploited + reaches a crown jewel;
 * ``Track*`` = no reachable impact today. Optional so pre-v3 agents still
 * validate.
 */
export const SsvcDecisionSchema = z.enum(['Act', 'Attend', 'Track', 'Track*']);

/**
 * Confidence in a finding's reachability. ``medium`` is set when reachability
 * depends on an *absent* control (e.g. no NetworkPolicy), so the operator
 * understands the score is "would-be" rather than observed.
 */
export const ConfidenceSchema = z.enum(['high', 'medium', 'n/a']);

export const ExposureSchema = z.enum(['open', 'internal', 'small', 'cluster']);

export const WireFindingSchema = z.object({
  id: ShortStr(),
  source: ShortStr(),
  ruleId: ShortStr(),
  title: Str(),
  description: Str(16384).optional(),
  severity: SeveritySchema,
  resource: ResourceRefSchema,
  reachable: z.boolean().optional(),
  exploitScore: z.number().finite().optional(),
  attackPathId: ShortStr().optional(),
  controls: z.array(ControlRefSchema).max(64).optional(),
  baseScore: z.number().finite().optional(),

  // --- v3 attack-graph fields (all optional; legacy agents omit) ----------
  /** CVE identifier when ``source === 'trivy'`` / type === 'cve'. */
  cve: ShortStr(64).optional(),
  /** Listed in the live CISA KEV catalogue at scan time. */
  kev: z.boolean().optional(),
  /** Tagged "Known Ransomware Campaign Use" in CISA KEV. */
  ransomware: z.boolean().optional(),
  /** EPSS probability (0..1) the CVE is exploited in the next 30 days. */
  epss: z.number().min(0).max(1).optional(),
  /** Stakeholder-Specific Vulnerability Categorization decision. */
  ssvc: SsvcDecisionSchema.optional(),
  /** Confidence in the reachability classification. */
  confidence: ConfidenceSchema.optional(),
  /** Exposure category from the attack graph (open / internal / small / cluster). */
  exposure: ExposureSchema.optional(),
  /** Crown-jewel categories this finding's path traverses (e.g. secret, cloud_admin). */
  reaches: z.array(ShortStr(64)).max(32).optional(),
});

export const WireAttackStepSchema = z.object({
  kind: ShortStr(),
  resource: ResourceRefSchema,
  detail: Str(),
  findingIds: z.array(ShortStr()).max(512),
});

export const WireAttackPathSchema = z.object({
  id: ShortStr(),
  narrative: Str(16384),
  score: z.number().finite(),
  entryPoint: ShortStr().optional(),
  steps: z.array(WireAttackStepSchema).max(128),
  findingIds: z.array(ShortStr()).max(2048),
});

export const WireRemediationSchema = z.object({
  id: ShortStr(),
  playbookId: ShortStr(),
  title: Str(),
  severity: SeveritySchema,
  kind: z.enum(['patch', 'new-file', 'manual']),
  rationale: Str(16384),
  path: ShortStr(1024),
  diff: Str(131072),
  manualSteps: z.array(Str()).max(64),
  controls: z.array(ControlRefSchema).max(64),
  findingIds: z.array(ShortStr()).max(2048),
  attackPathId: ShortStr().optional(),
  priority: z.number().finite(),
  branch: ShortStr(),
  prTitle: Str(),
  prBody: Str(131072),
});

export const WireAuditEntrySchema = z.object({
  seq: z.number().int().nonnegative(),
  ts: ShortStr(64),
  actor: ShortStr(64),
  agent: ShortStr(64).optional(),
  action: ShortStr(128),
  runId: ShortStr().optional(),
});

export const WireRunSchema = z.object({
  id: ShortStr(),
  status: z.enum(['running', 'complete', 'failed']),
  engine: ShortStr(),
  usedFixtures: z.boolean(),
  findingCount: z.number().int().nonnegative(),
  pathCount: z.number().int().nonnegative(),
  riskScore: z.number().finite().nullable(),
  summary: Str(16384).nullable(),
  startedAt: ShortStr(64),
  finishedAt: ShortStr(64).nullable().optional(),
});

/**
 * A complete posture push. This is the canonical "what leaves the cluster" set:
 * normalized findings, correlated attack paths, propose-only remediations, run
 * metadata, and audit entries — never secrets, raw manifests, or credentials
 * (those are excluded in-cluster before this is built).
 */
export const PostureSnapshotSchema = z.object({
  run: WireRunSchema,
  findings: z.array(WireFindingSchema).max(20000),
  paths: z.array(WireAttackPathSchema).max(2000),
  remediations: z.array(WireRemediationSchema).max(2000),
  audit: z.array(WireAuditEntrySchema).max(20000),
});

/** Live scan progress (display-only). Unknown keys are stripped at the boundary. */
export const WireAgentEventSchema = z.object({
  type: ShortStr(64),
  agent: ShortStr(64).optional(),
  text: Str().optional(),
  tool: ShortStr(128).optional(),
  message: Str().optional(),
  ts: ShortStr(64).optional(),
});

// --- Control commands -------------------------------------------------------

export const CommandKindSchema = z.enum(['scan', 'ask', 'approve', 'report']);
export type CommandKind = z.infer<typeof CommandKindSchema>;

// --- Message envelope (discriminated union on `t`) ---------------------------

/** agent → relay: first frame after dialing out. Token on first boot, or a known clusterId on reconnect. */
export const RegisterMsgSchema = z.object({
  t: z.literal('register'),
  protocol: z.number().int(),
  token: ShortStr(512).optional(),
  clusterId: ShortStr().optional(),
  agentVersion: ShortStr(64).optional(),
  clusterName: ShortStr().optional(),
  /** SHA-256 fingerprint of the mTLS client cert the relay terminated. */
  certFingerprint: ShortStr(128).optional(),
});

/** relay → agent: registration accepted; the agent is now bound to this cluster. */
export const RegisteredMsgSchema = z.object({
  t: z.literal('registered'),
  clusterId: ShortStr(),
  sessionId: ShortStr(),
});

/** control → relay: attach this control connection to a cluster's up-stream. */
export const SubscribeMsgSchema = z.object({
  t: z.literal('subscribe'),
  clusterId: ShortStr(),
});

/** relay → control: subscription accepted. */
export const SubscribedMsgSchema = z.object({
  t: z.literal('subscribed'),
  clusterId: ShortStr(),
});

export const PingMsgSchema = z.object({ t: z.literal('ping'), ts: z.number() });
export const PongMsgSchema = z.object({ t: z.literal('pong'), ts: z.number() });

/** control → agent (via relay): trigger a scan, NL query, approval, or report. */
export const CommandMsgSchema = z.object({
  t: z.literal('command'),
  id: ShortStr(),
  clusterId: ShortStr(),
  kind: CommandKindSchema,
  params: z.record(z.unknown()).optional(),
});

/** agent → control: command received (before any long-running work). */
export const AckMsgSchema = z.object({ t: z.literal('ack'), id: ShortStr() });

/** agent → control: a live scan progress event. */
export const EventMsgSchema = z.object({
  t: z.literal('event'),
  clusterId: ShortStr(),
  runId: ShortStr().optional(),
  event: WireAgentEventSchema,
});

/** agent → control: a full posture push to be persisted hosted-side. */
export const SnapshotMsgSchema = z.object({
  t: z.literal('snapshot'),
  clusterId: ShortStr(),
  snapshot: PostureSnapshotSchema,
});

/** agent → control: terminal response to a command (ask answer, approve outcome, …). */
export const ResultMsgSchema = z.object({
  t: z.literal('result'),
  id: ShortStr(),
  ok: z.boolean(),
  data: z.unknown().optional(),
  error: Str().optional(),
});

/** either direction: a protocol-level error. */
export const ErrorMsgSchema = z.object({
  t: z.literal('error'),
  code: ShortStr(64),
  message: Str(2048),
  id: ShortStr().optional(),
});

/** either direction: graceful close. */
export const ByeMsgSchema = z.object({ t: z.literal('bye'), reason: ShortStr().optional() });

export const MessageSchema = z.discriminatedUnion('t', [
  RegisterMsgSchema,
  RegisteredMsgSchema,
  SubscribeMsgSchema,
  SubscribedMsgSchema,
  PingMsgSchema,
  PongMsgSchema,
  CommandMsgSchema,
  AckMsgSchema,
  EventMsgSchema,
  SnapshotMsgSchema,
  ResultMsgSchema,
  ErrorMsgSchema,
  ByeMsgSchema,
]);

// --- Inferred types ----------------------------------------------------------

export type ResourceRef = z.infer<typeof ResourceRefSchema>;
export type ControlRef = z.infer<typeof ControlRefSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type WireFinding = z.infer<typeof WireFindingSchema>;
export type WireAttackStep = z.infer<typeof WireAttackStepSchema>;
export type WireAttackPath = z.infer<typeof WireAttackPathSchema>;
export type WireRemediation = z.infer<typeof WireRemediationSchema>;
export type WireAuditEntry = z.infer<typeof WireAuditEntrySchema>;
export type WireRun = z.infer<typeof WireRunSchema>;
export type PostureSnapshot = z.infer<typeof PostureSnapshotSchema>;
export type WireAgentEvent = z.infer<typeof WireAgentEventSchema>;

export type RegisterMsg = z.infer<typeof RegisterMsgSchema>;
export type RegisteredMsg = z.infer<typeof RegisteredMsgSchema>;
export type SubscribeMsg = z.infer<typeof SubscribeMsgSchema>;
export type SubscribedMsg = z.infer<typeof SubscribedMsgSchema>;
export type PingMsg = z.infer<typeof PingMsgSchema>;
export type PongMsg = z.infer<typeof PongMsgSchema>;
export type CommandMsg = z.infer<typeof CommandMsgSchema>;
export type AckMsg = z.infer<typeof AckMsgSchema>;
export type EventMsg = z.infer<typeof EventMsgSchema>;
export type SnapshotMsg = z.infer<typeof SnapshotMsgSchema>;
export type ResultMsg = z.infer<typeof ResultMsgSchema>;
export type ErrorMsg = z.infer<typeof ErrorMsgSchema>;
export type ByeMsg = z.infer<typeof ByeMsgSchema>;
export type Message = z.infer<typeof MessageSchema>;

// --- Codec (the trust-boundary chokepoint) -----------------------------------

export class ProtocolError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ProtocolError';
  }
}

/**
 * Serialize a message. Validates on the way out too, so a programming bug (a
 * malformed frame) is caught locally rather than rejected by the remote peer.
 */
export function encode(msg: Message): string {
  return JSON.stringify(MessageSchema.parse(msg));
}

/**
 * Parse + validate an inbound frame. Throws {@link ProtocolError} on oversize,
 * non-JSON, or any structural/limit violation — nothing unvalidated escapes.
 */
export function decode(data: string): Message {
  if (data.length > MAX_FRAME_BYTES) {
    throw new ProtocolError('frame_too_large', `frame exceeds ${MAX_FRAME_BYTES} bytes`);
  }
  let json: unknown;
  try {
    json = JSON.parse(data);
  } catch {
    throw new ProtocolError('bad_json', 'frame is not valid JSON');
  }
  const parsed = MessageSchema.safeParse(json);
  if (!parsed.success) {
    const detail = parsed.error.issues
      .slice(0, 5)
      .map((i) => `${i.path.join('.') || '<root>'}: ${i.message}`)
      .join('; ');
    throw new ProtocolError('bad_message', detail || 'frame failed schema validation');
  }
  return parsed.data;
}

// --- Transport (injectable, like HermesEngineConfig.fetchImpl) ---------------

/**
 * A bidirectional string-frame channel. The relay/agent/control logic depends
 * only on this; the production adapter wraps a WebSocket, tests use a memory
 * pair. Send is fire-and-forget; delivery and ordering are the adapter's job.
 */
export interface Transport {
  send(data: string): void;
  onMessage(handler: (data: string) => void): void;
  onClose(handler: () => void): void;
  close(): void;
  readonly closed: boolean;
}

/**
 * Two linked in-memory transports: `a.send` is delivered to `b`'s message
 * handlers (and vice-versa) on a microtask, so ordering is preserved and the
 * call stack stays shallow — close on either side propagates to the other.
 */
export function createMemoryTransportPair(): [Transport, Transport] {
  const a = new MemoryTransport();
  const b = new MemoryTransport();
  a.bind(b);
  b.bind(a);
  return [a, b];
}

class MemoryTransport implements Transport {
  private peer: MemoryTransport | undefined;
  private readonly messageHandlers: ((d: string) => void)[] = [];
  private readonly closeHandlers: (() => void)[] = [];
  private _closed = false;

  get closed(): boolean {
    return this._closed;
  }

  bind(peer: MemoryTransport): void {
    this.peer = peer;
  }

  send(data: string): void {
    if (this._closed) throw new Error('transport is closed');
    const peer = this.peer;
    if (!peer) return;
    // Defer to a microtask: preserves order, mimics async delivery, avoids
    // unbounded synchronous recursion across the pair.
    void Promise.resolve().then(() => {
      if (peer._closed) return;
      for (const h of peer.messageHandlers) h(data);
    });
  }

  onMessage(handler: (d: string) => void): void {
    this.messageHandlers.push(handler);
  }

  onClose(handler: () => void): void {
    this.closeHandlers.push(handler);
  }

  close(): void {
    if (this._closed) return;
    this._closed = true;
    for (const h of this.closeHandlers) h();
    const peer = this.peer;
    if (peer && !peer._closed) void Promise.resolve().then(() => peer.close());
  }
}
