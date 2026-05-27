import {
  PROTOCOL_VERSION,
  ProtocolError,
  decode,
  encode,
  type CommandMsg,
  type Message,
  type PostureSnapshot,
  type Transport,
  type WireAgentEvent,
} from '@k8s-sentinel/relay-protocol';

/**
 * In-cluster tunnel-client (Phase 5, hybrid mode — docs/DATA-BOUNDARY.md).
 *
 * Drives ONE session over the injectable {@link Transport}: it sends `register`,
 * then services control commands flowing DOWN (scan/ask/approve/report) by
 * invoking the supplied {@link TunnelHandlers} (which wrap the existing
 * orchestrator/reporting — behaviour is identical to the SSE server). Results
 * flow UP as `ack` → live `event`s → terminal `snapshot`/`result`.
 *
 * It is read-only and propose-only by construction: it only ever *reports* a
 * posture and *proposes* fixes; nothing it does mutates the cluster. The dialing,
 * mTLS, and reconnect concerns live in ws-client.ts / connect.ts, so this class
 * is exercised end-to-end offline over an in-memory transport pair.
 */
export class TunnelClient {
  private clusterId?: string;
  private readonly log: TunnelLogger;
  private registeredResolve?: (clusterId: string) => void;
  private registeredReject?: (err: Error) => void;
  private settled = false;

  /** Resolves when the transport closes — drives the reconnect loop in connect.ts. */
  readonly whenClosed: Promise<void>;
  private closedResolve!: () => void;

  constructor(private readonly opts: TunnelClientOptions) {
    this.log = opts.log ?? (() => {});
    this.whenClosed = new Promise((r) => (this.closedResolve = r));
    opts.transport.onMessage((d) => {
      void this.onMessage(d);
    });
    opts.transport.onClose(() => {
      if (!this.settled) this.registeredReject?.(new Error('transport closed before registration'));
      this.closedResolve();
      this.opts.onClose?.();
    });
  }

  /** Send `register`; resolves with the clusterId once the relay confirms. */
  start(): Promise<string> {
    const p = new Promise<string>((resolve, reject) => {
      this.registeredResolve = resolve;
      this.registeredReject = reject;
    });
    this.send({ t: 'register', protocol: PROTOCOL_VERSION, ...this.opts.register });
    return p;
  }

  close(): void {
    this.opts.transport.close();
  }

  private send(msg: Message): void {
    if (!this.opts.transport.closed) this.opts.transport.send(encode(msg));
  }

  private async onMessage(data: string): Promise<void> {
    let msg: Message;
    try {
      msg = decode(data);
    } catch (e) {
      this.log('warn', 'discarding malformed frame from relay', { err: (e as ProtocolError).message });
      return;
    }
    switch (msg.t) {
      case 'registered':
        this.clusterId = msg.clusterId;
        this.settled = true;
        this.registeredResolve?.(msg.clusterId);
        this.opts.onRegistered?.(msg.clusterId);
        this.log('info', 'tunnel registered', { clusterId: msg.clusterId, sessionId: msg.sessionId });
        return;
      case 'command':
        return this.handleCommand(msg);
      case 'ping':
        return this.send({ t: 'pong', ts: msg.ts });
      case 'pong':
        return;
      case 'error':
        this.log('warn', 'relay error', { code: msg.code, message: msg.message });
        return;
      case 'bye':
        this.log('info', 'relay closed the tunnel', { reason: msg.reason });
        this.close();
        return;
      default:
        // registered/subscribed/ack/event/snapshot/result are server-bound; ignore.
        return;
    }
  }

  private async handleCommand(cmd: CommandMsg): Promise<void> {
    this.send({ t: 'ack', id: cmd.id });
    const clusterId = this.clusterId ?? cmd.clusterId;
    const params = cmd.params ?? {};
    try {
      if (cmd.kind === 'scan') {
        const emit = (event: WireAgentEvent): void => this.send({ t: 'event', clusterId, event });
        const snapshot: PostureSnapshot = await this.opts.handlers.scan(params, emit);
        this.send({ t: 'snapshot', clusterId, snapshot });
        this.send({ t: 'result', id: cmd.id, ok: true, data: { runId: snapshot.run.id } });
        return;
      }
      let data: unknown;
      if (cmd.kind === 'ask') {
        data = await this.opts.handlers.ask(str(params, 'query'));
      } else if (cmd.kind === 'approve') {
        data = await this.opts.handlers.approve(str(params, 'fixId'), optStr(params, 'runId'));
      } else {
        data = await this.opts.handlers.report(str(params, 'format') || 'md', optStr(params, 'runId'));
      }
      this.send({ t: 'result', id: cmd.id, ok: true, data });
    } catch (e) {
      this.send({ t: 'result', id: cmd.id, ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  }
}

export interface TunnelHandlers {
  /** Run a full scan; stream progress via `emit`, return the posture snapshot. */
  scan(params: Record<string, unknown>, emit: (ev: WireAgentEvent) => void): Promise<PostureSnapshot>;
  /** Answer a plain-English query over the latest posture. */
  ask(query: string): Promise<unknown>;
  /** Approve a fix → writes a reviewable PR bundle; returns its metadata. */
  approve(fixId: string, runId: string | undefined): Promise<unknown>;
  /** Render a report → returns metadata (bytes are fetched separately, not over a command). */
  report(format: string, runId: string | undefined): Promise<unknown>;
}

export interface TunnelClientOptions {
  transport: Transport;
  register: { token?: string; clusterId?: string; agentVersion?: string; clusterName?: string };
  handlers: TunnelHandlers;
  log?: TunnelLogger;
  onRegistered?: (clusterId: string) => void;
  onClose?: () => void;
}

export type TunnelLogger = (
  level: 'info' | 'warn' | 'error',
  msg: string,
  meta?: Record<string, unknown>,
) => void;

function str(params: Record<string, unknown>, key: string): string {
  const v = params[key];
  return typeof v === 'string' ? v : '';
}

function optStr(params: Record<string, unknown>, key: string): string | undefined {
  const v = params[key];
  return typeof v === 'string' ? v : undefined;
}
