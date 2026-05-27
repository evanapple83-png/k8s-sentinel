import type { WebSocket } from 'ws';
import type { Transport } from '@k8s-sentinel/relay-protocol';

/**
 * Adapt a `ws` WebSocket to the protocol's {@link Transport}. This is the only
 * place the relay touches the wire library — the routing/identity logic in
 * relay.ts stays transport-agnostic and offline-testable.
 */
export function wsTransport(ws: WebSocket): Transport {
  let closed = false;
  return {
    get closed() {
      return closed;
    },
    send(data) {
      // OPEN === 1 in the ws ready-state enum.
      if (!closed && ws.readyState === 1) ws.send(data);
    },
    onMessage(handler) {
      ws.on('message', (raw: unknown) => handler(String(raw)));
    },
    onClose(handler) {
      ws.on('close', () => {
        closed = true;
        handler();
      });
      ws.on('error', () => {
        closed = true;
        handler();
      });
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
