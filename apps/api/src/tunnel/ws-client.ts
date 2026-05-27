import WebSocket from 'ws';
import type { Transport } from '@k8s-sentinel/relay-protocol';

/**
 * Dial the relay over a WebSocket and resolve once connected. The agent always
 * dials OUT — there is no inbound port (docs/DATA-BOUNDARY.md). In production the
 * URL is `wss://…` and the mTLS client cert/key are supplied so the relay can
 * bind the connection to a clusterId from the cert CN.
 */
export interface DialOptions {
  url: string;
  /** Sent on the upgrade request (not used by agents, but handy for parity). */
  headers?: Record<string, string>;
  /** mTLS client material (PEM). Omitted on first boot (token bootstrap). */
  cert?: string | Buffer;
  key?: string | Buffer;
  ca?: string | Buffer;
  handshakeTimeoutMs?: number;
}

export function dialRelay(opts: DialOptions): Promise<Transport> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(opts.url, {
      headers: opts.headers,
      cert: opts.cert,
      key: opts.key,
      ca: opts.ca,
      handshakeTimeout: opts.handshakeTimeoutMs ?? 15_000,
      maxPayload: 8 * 1024 * 1024,
    });
    const onError = (err: Error) => {
      ws.removeAllListeners();
      reject(err);
    };
    ws.once('error', onError);
    ws.once('open', () => {
      ws.off('error', onError);
      resolve(wsClientTransport(ws));
    });
  });
}

/** Adapt a connected `ws` socket to the protocol {@link Transport}. */
export function wsClientTransport(ws: WebSocket): Transport {
  let closed = false;
  return {
    get closed() {
      return closed;
    },
    send(data) {
      if (!closed && ws.readyState === WebSocket.OPEN) ws.send(data);
    },
    onMessage(handler) {
      ws.on('message', (raw: unknown) => handler(String(raw)));
    },
    onClose(handler) {
      const fire = () => {
        if (!closed) {
          closed = true;
          handler();
        }
      };
      ws.on('close', fire);
      ws.on('error', fire);
    },
    close() {
      if (closed) return;
      closed = true;
      try {
        ws.close();
      } catch {
        /* already gone */
      }
    },
  };
}
