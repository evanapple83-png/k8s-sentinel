import { describe, expect, it } from 'vitest';
import { createMemoryTransportPair, decode, encode, type PostureSnapshot } from '@k8s-sentinel/relay-protocol';
import { connectTunnel } from './connect.js';
import type { TunnelHandlers } from './client.js';

function stubHandlers(): TunnelHandlers {
  const snap: PostureSnapshot = {
    run: {
      id: 'r',
      status: 'complete',
      engine: 'claude',
      usedFixtures: true,
      findingCount: 0,
      pathCount: 0,
      riskScore: 0,
      summary: null,
      startedAt: '2026-05-27T00:00:00.000Z',
    },
    findings: [],
    paths: [],
    remediations: [],
    audit: [],
  };
  return {
    scan: async () => snap,
    ask: async () => ({}),
    approve: async () => ({}),
    report: async () => ({}),
  };
}

describe('connectTunnel reconnect loop', () => {
  it('redials and re-registers after each disconnect until running() is false', async () => {
    let dials = 0;
    let registers = 0;

    const dial = async () => {
      dials++;
      const [relaySide, clientSide] = createMemoryTransportPair();
      relaySide.onMessage((d) => {
        if (decode(d).t === 'register') {
          relaySide.send(encode({ t: 'registered', clusterId: 'c1', sessionId: 's' }));
          setTimeout(() => relaySide.close(), 0); // end the session shortly after
        }
      });
      return clientSide;
    };

    await connectTunnel({
      dial,
      register: { token: 't' },
      handlers: stubHandlers(),
      sleep: async () => {},
      onRegistered: () => registers++,
      running: () => dials < 3,
    });

    expect(dials).toBe(3);
    expect(registers).toBe(3);
  });

  it('retries with backoff when the dial itself fails', async () => {
    let dials = 0;
    const dial = async () => {
      dials++;
      throw new Error('connection refused');
    };
    let slept = 0;
    await connectTunnel({
      dial,
      register: {},
      handlers: stubHandlers(),
      sleep: async () => {
        slept++;
      },
      running: () => dials < 2,
    });
    expect(dials).toBe(2);
    expect(slept).toBeGreaterThanOrEqual(1);
  });
});
