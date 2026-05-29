import { EventEmitter } from 'node:events';
import { describe, expect, it } from 'vitest';
import { wsClientTransport } from './ws-client.js';

/**
 * Regression for the issue #11 reconnect stall: a relay-initiated `bye` makes
 * the client call transport.close(), and the close handler MUST still fire so
 * the reconnect loop (connectTunnel: `await whenClosed`) wakes up. The old guard
 * (`if (!closed)`) swallowed the ws 'close' event once close() had set closed,
 * so the agent process stranded and exited instead of reconnecting.
 */
class FakeWs extends EventEmitter {
  readyState = 1; // OPEN
  sent: unknown[] = [];
  send(d: unknown) {
    this.sent.push(d);
  }
  close() {
    this.readyState = 3;
    this.emit('close');
  }
}

describe('wsClientTransport onClose', () => {
  it('fires the close handler on a LOCAL close() (relay bye path)', () => {
    const ws = new FakeWs();
    const t = wsClientTransport(ws as never);
    let closeCalls = 0;
    t.onClose(() => closeCalls++);

    t.close(); // local close, as triggered by a relay `bye`

    expect(closeCalls).toBe(1);
    expect(t.closed).toBe(true);
  });

  it('fires the close handler on a REMOTE close', () => {
    const ws = new FakeWs();
    const t = wsClientTransport(ws as never);
    let closeCalls = 0;
    t.onClose(() => closeCalls++);

    ws.emit('close');

    expect(closeCalls).toBe(1);
    expect(t.closed).toBe(true);
  });

  it('fires exactly once even across multiple close/error events', () => {
    const ws = new FakeWs();
    const t = wsClientTransport(ws as never);
    let closeCalls = 0;
    t.onClose(() => closeCalls++);

    ws.emit('error', new Error('boom'));
    ws.emit('close');
    t.close();

    expect(closeCalls).toBe(1);
  });
});
