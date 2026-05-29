import type { Transport } from '@k8s-sentinel/relay-protocol';
import { TunnelClient, type TunnelHandlers, type TunnelLogger } from './client.js';

/**
 * Long-lived tunnel runner: dial → register → serve commands until the session
 * closes, then reconnect with exponential backoff. Dialing and sleeping are
 * injected so the loop is testable offline (memory transports, no real timers).
 */
export interface ConnectTunnelOptions {
  dial: () => Promise<Transport>;
  register: { token?: string; clusterId?: string; agentVersion?: string; clusterName?: string; reconnectToken?: string };
  handlers: TunnelHandlers;
  log?: TunnelLogger;
  onRegistered?: (clusterId: string, reconnectToken?: string) => void;
  sleep?: (ms: number) => Promise<void>;
  backoff?: { baseMs?: number; maxMs?: number };
  /** Return false to stop the loop (shutdown / tests). Defaults to forever. */
  running?: () => boolean;
}

export async function connectTunnel(opts: ConnectTunnelOptions): Promise<void> {
  const log = opts.log ?? (() => {});
  const sleep = opts.sleep ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms)));
  const running = opts.running ?? (() => true);
  const baseMs = opts.backoff?.baseMs ?? 1_000;
  const maxMs = opts.backoff?.maxMs ?? 30_000;
  let attempt = 0;

  // First-boot registration returns a durable reconnect token (issue #11). Once
  // we hold it, switch the register payload to {clusterId, reconnectToken} and
  // drop the now-consumed single-use install token — so reconnects survive a
  // tunnel drop instead of looping on "registration rejected". Mutating the
  // shared `register` object means every subsequent TunnelClient picks it up.
  const onRegistered = (clusterId: string, reconnectToken?: string): void => {
    opts.register.clusterId = clusterId;
    if (reconnectToken) {
      opts.register.reconnectToken = reconnectToken;
      delete opts.register.token;
    }
    opts.onRegistered?.(clusterId, reconnectToken);
  };

  while (running()) {
    let transport: Transport;
    try {
      transport = await opts.dial();
      attempt = 0;
    } catch (e) {
      log('warn', 'relay dial failed; will retry', { err: String(e), attempt });
      await sleep(backoffDelay(baseMs, maxMs, attempt++));
      continue;
    }

    const client = new TunnelClient({
      transport,
      register: opts.register,
      handlers: opts.handlers,
      log,
      onRegistered,
    });
    try {
      await client.start();
    } catch (e) {
      log('warn', 'registration failed; reconnecting', { err: String(e) });
    }

    await client.whenClosed;
    if (!running()) break;
    log('info', 'tunnel closed; reconnecting', { attempt });
    await sleep(backoffDelay(baseMs, maxMs, attempt++));
  }
}

/** Exponential backoff with full jitter, capped at maxMs. */
function backoffDelay(baseMs: number, maxMs: number, attempt: number): number {
  const ceil = Math.min(maxMs, baseMs * 2 ** Math.min(attempt, 16));
  return Math.floor(Math.random() * ceil);
}
