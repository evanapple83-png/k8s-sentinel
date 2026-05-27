import {
  PROTOCOL_VERSION,
  ProtocolError,
  decode,
  encode,
  type CommandKind,
  type Message,
  type PostureSnapshot,
  type RegisterMsg,
  type ResultMsg,
  type SubscribeMsg,
  type Transport,
} from '@k8s-sentinel/relay-protocol';

/**
 * The relay (Phase 5, hybrid mode — docs/DATA-BOUNDARY.md).
 *
 * A **stateless** message broker between the in-cluster **agent** (dials out)
 * and the hosted **control plane**. It holds only live connection references
 * keyed by `clusterId` — it never persists a single posture payload, never
 * inspects findings, and forwards frames in both directions:
 *
 *   control --command/ping-->  [relay]  --command-->  agent
 *   agent   --event/snapshot/ack/result-->  [relay]  --forward-->  controls
 *
 * Security posture:
 *  - An agent is authenticated by {@link RelayDeps.verifyAgent} (install token
 *    on first boot, mTLS cert fingerprint thereafter) which RESOLVES the
 *    clusterId. The agent's self-declared clusterId is never trusted.
 *  - Every forwarded `event`/`snapshot` is RE-STAMPED with the connection's
 *    bound clusterId, so a compromised agent cannot inject another tenant's id.
 *  - A control may only command the cluster it subscribed to (and was
 *    authorized for via {@link RelayDeps.authorizeControl}).
 *
 * Transport-agnostic: it operates over the injectable {@link Transport}, so the
 * full routing/identity logic is unit-tested offline over an in-memory pair;
 * `ws-transport.ts` is the thin production adapter.
 */
export class Relay {
  /** At most one live agent per cluster (newest registration supersedes). */
  private readonly agents = new Map<string, Conn>();
  /** Control subscribers per cluster. */
  private readonly controls = new Map<string, Set<Conn>>();
  /** In-flight HTTP-bridged commands awaiting their `result` (RPC correlation). */
  private readonly pending = new Map<string, { resolve: (r: ResultMsg) => void; timer: ReturnType<typeof setTimeout> }>();
  private readonly now: () => number;
  private readonly genId: () => string;
  private readonly log: RelayLogger;

  constructor(private readonly deps: RelayDeps) {
    this.now = deps.now ?? (() => Date.now());
    this.genId = deps.genId ?? defaultGenId;
    this.log = deps.log ?? (() => {});
  }

  /** Wire a freshly accepted transport into the relay. */
  accept(transport: Transport, ctx: ConnContext = {}): void {
    const conn = new Conn(transport, ctx, this.now());
    transport.onMessage((data) => {
      void this.onMessage(conn, data);
    });
    transport.onClose(() => this.onClose(conn));
  }

  /** Live counts (for health/metrics + tests). Never exposes payloads. */
  stats(): { agents: number; controlConnections: number; clusters: number } {
    let controlConnections = 0;
    for (const set of this.controls.values()) controlConnections += set.size;
    const clusters = new Set([...this.agents.keys(), ...this.controls.keys()]);
    return { agents: this.agents.size, controlConnections, clusters: clusters.size };
  }

  /**
   * Evict connections idle longer than `idleMs`. The server calls this on an
   * interval (kept external so the relay holds no timers and stays testable).
   */
  sweep(idleMs: number): number {
    const cutoff = this.now() - idleMs;
    let evicted = 0;
    for (const conn of this.allConns()) {
      if (conn.lastSeen < cutoff) {
        conn.sendMsg({ t: 'bye', reason: 'idle timeout' });
        conn.transport.close();
        evicted++;
      }
    }
    return evicted;
  }

  private *allConns(): Iterable<Conn> {
    yield* this.agents.values();
    for (const set of this.controls.values()) yield* set;
  }

  /**
   * Request/response over the tunnel: send a command to a cluster's agent and
   * resolve with its `result`. Lets the hosted control plane drive "scan now" /
   * "ask" over a stateless HTTP call (it need not hold a WebSocket). Resolves
   * with `ok:false` rather than rejecting, so callers always get a clean answer.
   */
  sendCommand(
    clusterId: string,
    kind: CommandKind,
    params: Record<string, unknown> | undefined,
    timeoutMs = 120_000,
  ): Promise<ResultMsg> {
    const id = this.genId();
    const agent = this.agents.get(clusterId);
    if (!agent) return Promise.resolve({ t: 'result', id, ok: false, error: 'agent offline' });

    return new Promise<ResultMsg>((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve({ t: 'result', id, ok: false, error: 'command timed out' });
      }, timeoutMs);
      timer.unref?.();
      this.pending.set(id, { resolve, timer });
      agent.sendMsg({ t: 'command', id, clusterId, kind, params });
    });
  }

  private async onMessage(conn: Conn, data: string): Promise<void> {
    let msg: Message;
    try {
      msg = decode(data);
    } catch (e) {
      const err = e as ProtocolError;
      conn.sendMsg({ t: 'error', code: err.code ?? 'bad_message', message: err.message });
      return;
    }
    conn.lastSeen = this.now();
    try {
      if (conn.role === 'unknown') {
        await this.identify(conn, msg);
      } else if (conn.role === 'agent') {
        this.fromAgent(conn, msg);
      } else {
        this.fromControl(conn, msg);
      }
    } catch (e) {
      this.log('error', 'message handling failed', { err: String(e), t: msg.t });
      conn.sendMsg({ t: 'error', code: 'internal', message: 'message handling failed' });
    }
  }

  /** First frame must declare a role: `register` (agent) or `subscribe` (control). */
  private async identify(conn: Conn, msg: Message): Promise<void> {
    if (msg.t === 'register') return this.registerAgent(conn, msg);
    if (msg.t === 'subscribe') return this.subscribeControl(conn, msg);
    if (msg.t === 'ping') return conn.sendMsg({ t: 'pong', ts: msg.ts });
    if (msg.t === 'bye') return conn.transport.close();
    conn.sendMsg({ t: 'error', code: 'not_identified', message: 'send register or subscribe first' });
  }

  private async registerAgent(conn: Conn, reg: RegisterMsg): Promise<void> {
    if (reg.protocol !== PROTOCOL_VERSION) {
      conn.sendMsg({ t: 'error', code: 'protocol_mismatch', message: `relay speaks protocol v${PROTOCOL_VERSION}` });
      conn.transport.close();
      return;
    }
    let clusterId: string;
    try {
      ({ clusterId } = await this.deps.verifyAgent(reg, conn.ctx));
    } catch (e) {
      this.log('warn', 'agent registration rejected', { err: String(e), remote: conn.ctx.remote });
      conn.sendMsg({ t: 'error', code: 'unauthorized', message: 'agent registration rejected' });
      conn.transport.close();
      return;
    }

    conn.role = 'agent';
    conn.clusterId = clusterId;
    conn.sessionId = this.genId();

    // Newest agent for a cluster wins (re-deploy / pod restart); retire the old one.
    const prev = this.agents.get(clusterId);
    if (prev && prev !== conn) {
      prev.sendMsg({ t: 'bye', reason: 'superseded by a newer agent' });
      prev.transport.close();
    }
    this.agents.set(clusterId, conn);
    conn.sendMsg({ t: 'registered', clusterId, sessionId: conn.sessionId });
    this.log('info', 'agent registered', { clusterId, remote: conn.ctx.remote });
  }

  private async subscribeControl(conn: Conn, sub: SubscribeMsg): Promise<void> {
    try {
      await this.deps.authorizeControl(sub, conn.ctx);
    } catch (e) {
      this.log('warn', 'control subscription rejected', { err: String(e), clusterId: sub.clusterId });
      conn.sendMsg({ t: 'error', code: 'unauthorized', message: 'subscription rejected' });
      conn.transport.close();
      return;
    }
    conn.role = 'control';
    conn.clusterId = sub.clusterId;
    let set = this.controls.get(sub.clusterId);
    if (!set) {
      set = new Set();
      this.controls.set(sub.clusterId, set);
    }
    set.add(conn);
    conn.sendMsg({ t: 'subscribed', clusterId: sub.clusterId });
  }

  private fromAgent(conn: Conn, msg: Message): void {
    const clusterId = conn.clusterId!;
    switch (msg.t) {
      case 'ping':
        return conn.sendMsg({ t: 'pong', ts: msg.ts });
      case 'pong':
        return;
      case 'bye':
        return conn.transport.close();
      case 'result': {
        // Resolve a pending HTTP-bridged command, then also fan out to controls.
        const p = this.pending.get(msg.id);
        if (p) {
          clearTimeout(p.timer);
          this.pending.delete(msg.id);
          p.resolve(msg);
        }
        return this.toControls(clusterId, msg);
      }
      case 'ack':
      case 'error':
        return this.toControls(clusterId, msg);
      case 'event':
        // Re-stamp with the bound clusterId — never trust the agent's claim.
        return this.toControls(clusterId, { ...msg, clusterId });
      case 'snapshot': {
        const stamped = { ...msg, clusterId };
        this.toControls(clusterId, stamped);
        // Durable ingest path: hand the posture to the hosted plane (webhook).
        if (this.deps.onSnapshot) {
          void Promise.resolve(this.deps.onSnapshot(clusterId, msg.snapshot)).catch((e) =>
            this.log('error', 'onSnapshot hook failed', { clusterId, err: String(e) }),
          );
        }
        return;
      }
      case 'register':
        return conn.sendMsg({ t: 'error', code: 'already_registered', message: 'agent already registered' });
      default:
        return conn.sendMsg({ t: 'error', code: 'unexpected', message: `agents may not send "${msg.t}"` });
    }
  }

  private fromControl(conn: Conn, msg: Message): void {
    const clusterId = conn.clusterId!;
    switch (msg.t) {
      case 'ping':
        return conn.sendMsg({ t: 'pong', ts: msg.ts });
      case 'pong':
        return;
      case 'bye':
        return conn.transport.close();
      case 'command': {
        const agent = this.agents.get(clusterId);
        if (!agent) {
          // Tell the caller synchronously rather than silently dropping.
          return conn.sendMsg({ t: 'result', id: msg.id, ok: false, error: 'agent offline' });
        }
        // Stamp the subscribed clusterId; a control can only drive its own cluster.
        return agent.sendMsg({ ...msg, clusterId });
      }
      case 'subscribe':
        return conn.sendMsg({ t: 'error', code: 'already_subscribed', message: 'already subscribed' });
      default:
        return conn.sendMsg({ t: 'error', code: 'unexpected', message: `controls may not send "${msg.t}"` });
    }
  }

  private toControls(clusterId: string, msg: Message): void {
    const set = this.controls.get(clusterId);
    if (!set || set.size === 0) {
      this.log('info', 'no control subscribed; dropping frame', { clusterId, t: msg.t });
      return;
    }
    for (const c of set) c.sendMsg(msg);
  }

  private onClose(conn: Conn): void {
    if (conn.role === 'agent' && conn.clusterId) {
      if (this.agents.get(conn.clusterId) === conn) {
        this.agents.delete(conn.clusterId);
        this.log('info', 'agent disconnected', { clusterId: conn.clusterId });
      }
    } else if (conn.role === 'control' && conn.clusterId) {
      const set = this.controls.get(conn.clusterId);
      set?.delete(conn);
      if (set && set.size === 0) this.controls.delete(conn.clusterId);
    }
  }
}

// --- Dependencies (all injectable) ------------------------------------------

export interface ConnContext {
  /** SHA-256 fingerprint of the terminated mTLS client cert, if any. */
  certFingerprint?: string;
  /** Common Name of the validated client cert. Issuance binds CN = clusterId. */
  certCommonName?: string;
  /** Secret/bearer the control plane presents (validated by authorizeControl). */
  authToken?: string;
  /** Remote address — logs only. */
  remote?: string;
}

export interface AgentIdentity {
  clusterId: string;
}

export interface RelayDeps {
  /** Authenticate an agent's register frame and resolve its clusterId, or throw. */
  verifyAgent(reg: RegisterMsg, ctx: ConnContext): Promise<AgentIdentity>;
  /** Authorize a control subscription to a cluster, or throw. */
  authorizeControl(sub: SubscribeMsg, ctx: ConnContext): Promise<void>;
  /**
   * Durable ingest hook: invoked with each posture an agent pushes. The server
   * wires this to an HTTP webhook into the hosted control plane. Optional so the
   * relay stays a pure forwarder when no hosted plane is configured.
   */
  onSnapshot?(clusterId: string, snapshot: PostureSnapshot): void | Promise<void>;
  now?: () => number;
  genId?: () => string;
  log?: RelayLogger;
}

export type RelayLogger = (
  level: 'info' | 'warn' | 'error',
  msg: string,
  meta?: Record<string, unknown>,
) => void;

type Role = 'unknown' | 'agent' | 'control';

class Conn {
  role: Role = 'unknown';
  clusterId?: string;
  sessionId?: string;
  lastSeen: number;

  constructor(
    readonly transport: Transport,
    readonly ctx: ConnContext,
    now: number,
  ) {
    this.lastSeen = now;
  }

  sendMsg(msg: Message): void {
    if (!this.transport.closed) this.transport.send(encode(msg));
  }
}

function defaultGenId(): string {
  return `sess-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}
