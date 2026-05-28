import { describe, expect, it, vi } from 'vitest';
import {
  MAX_FRAME_BYTES,
  PROTOCOL_VERSION,
  PostureSnapshotSchema,
  ProtocolError,
  createMemoryTransportPair,
  decode,
  encode,
  type Message,
  type PostureSnapshot,
} from './index.js';

function sampleSnapshot(): PostureSnapshot {
  return {
    run: {
      id: 'run-1',
      status: 'complete',
      engine: 'claude',
      usedFixtures: true,
      findingCount: 1,
      pathCount: 1,
      riskScore: 72,
      summary: 'one reachable critical',
      startedAt: '2026-05-27T00:00:00.000Z',
      finishedAt: '2026-05-27T00:01:00.000Z',
    },
    findings: [
      {
        id: 'f1',
        source: 'trivy',
        ruleId: 'CVE-2024-0001',
        title: 'critical RCE in payment-api',
        severity: 'critical',
        resource: { kind: 'Deployment', name: 'payment-api', namespace: 'prod' },
        reachable: true,
        exploitScore: 9.1,
        attackPathId: 'p1',
      },
    ],
    paths: [
      {
        id: 'p1',
        narrative: 'exposed → running → vulnerable → over-privileged',
        score: 88,
        entryPoint: 'internet',
        steps: [
          {
            kind: 'exposed',
            resource: { kind: 'Service', name: 'payment-api' },
            detail: 'LoadBalancer on 0.0.0.0',
            findingIds: ['f1'],
          },
        ],
        findingIds: ['f1'],
      },
    ],
    remediations: [],
    audit: [{ seq: 0, ts: '2026-05-27T00:00:00.000Z', actor: 'agent', action: 'scan.start', runId: 'run-1' }],
  };
}

describe('codec', () => {
  it('round-trips every message variant', () => {
    const msgs: Message[] = [
      { t: 'register', protocol: PROTOCOL_VERSION, token: 'sk-install-abc', clusterName: 'prod' },
      { t: 'registered', clusterId: 'c1', sessionId: 's1' },
      { t: 'subscribe', clusterId: 'c1' },
      { t: 'subscribed', clusterId: 'c1' },
      { t: 'ping', ts: 1 },
      { t: 'pong', ts: 1 },
      { t: 'command', id: 'cmd1', clusterId: 'c1', kind: 'scan' },
      { t: 'command', id: 'cmd2', clusterId: 'c1', kind: 'ask', params: { query: 'what is exposed?' } },
      { t: 'ack', id: 'cmd1' },
      { t: 'event', clusterId: 'c1', runId: 'run-1', event: { type: 'message', text: 'scanning…' } },
      { t: 'snapshot', clusterId: 'c1', snapshot: sampleSnapshot() },
      { t: 'result', id: 'cmd2', ok: true, data: { answer: 'payment-api' } },
      { t: 'error', code: 'bad_message', message: 'nope', id: 'cmd2' },
      { t: 'bye', reason: 'shutdown' },
    ];
    for (const msg of msgs) {
      expect(decode(encode(msg))).toEqual(msg);
    }
  });

  it('strips unknown keys from agent events at the boundary', () => {
    const wire = JSON.stringify({
      t: 'event',
      clusterId: 'c1',
      event: { type: 'message', text: 'hi', secretToken: 'leak-me' },
    });
    const msg = decode(wire);
    if (msg.t !== 'event') throw new Error('expected event');
    expect(msg.event).toEqual({ type: 'message', text: 'hi' });
    expect('secretToken' in msg.event).toBe(false);
  });

  it('rejects non-JSON frames', () => {
    expect(() => decode('not json {')).toThrowError(ProtocolError);
    try {
      decode('not json {');
    } catch (e) {
      expect((e as ProtocolError).code).toBe('bad_json');
    }
  });

  it('rejects unknown message types', () => {
    expect(() => decode(JSON.stringify({ t: 'hack', payload: 1 }))).toThrowError(ProtocolError);
  });

  it('rejects a frame over the size cap without parsing it', () => {
    const huge = 'x'.repeat(MAX_FRAME_BYTES + 1);
    try {
      decode(huge);
      throw new Error('should have thrown');
    } catch (e) {
      expect((e as ProtocolError).code).toBe('frame_too_large');
    }
  });

  it('rejects a snapshot whose finding is missing a required field', () => {
    const bad = {
      t: 'snapshot',
      clusterId: 'c1',
      snapshot: { ...sampleSnapshot(), findings: [{ id: 'f1' }] },
    };
    expect(() => decode(JSON.stringify(bad))).toThrowError(ProtocolError);
  });

  it('caps unbounded arrays (DoS guard)', () => {
    const oversized = {
      ...sampleSnapshot(),
      paths: Array.from({ length: 2001 }, (_, i) => ({
        id: `p${i}`,
        narrative: 'x',
        score: 1,
        steps: [],
        findingIds: [],
      })),
    };
    expect(PostureSnapshotSchema.safeParse(oversized).success).toBe(false);
  });

  it('encode validates outbound frames too', () => {
    // @ts-expect-error — deliberately malformed to prove encode guards
    expect(() => encode({ t: 'ping' })).toThrow();
  });

  it('accepts a snapshot carrying v3 intel + choke-points', () => {
    const snap = sampleSnapshot();
    snap.intel = {
      source: 'live:cisa-kev',
      version: '2026.05.27',
      kevCount: 1607,
      epssCount: 218_543,
    };
    snap.chokePoints = [
      {
        id: 'cp-1',
        control: { type: 'patch', ref: 'CVE-2026-31337', workload: 'payments/invoice-api' },
        breaks: 4,
        totalPaths: 4,
        targets: ['secret:payments/db-credentials', 'CLUSTER-ADMIN'],
        severity: 'critical',
        description: 'Patch CVE-2026-31337 on payments/invoice-api',
        priority: 4,
      },
    ];
    expect(() =>
      decode(encode({ t: 'snapshot', clusterId: 'c1', snapshot: snap })),
    ).not.toThrow();
  });

  it('caps choke-point arrays (DoS guard)', () => {
    const snap = sampleSnapshot();
    snap.chokePoints = Array.from({ length: 257 }, (_, i) => ({
      id: `cp-${i}`,
      control: { type: 'patch' },
      breaks: 1,
      totalPaths: 1,
      targets: [],
      severity: 'low' as const,
      description: 'x',
      priority: 1,
    }));
    expect(PostureSnapshotSchema.safeParse(snap).success).toBe(false);
  });

  it('still validates pre-v3 snapshots that omit intel + chokePoints', () => {
    const snap = sampleSnapshot();
    // Sanity: the baseline fixture has no v3 fields and must keep validating.
    expect('intel' in snap).toBe(false);
    expect('chokePoints' in snap).toBe(false);
    expect(PostureSnapshotSchema.safeParse(snap).success).toBe(true);
  });
});

describe('memory transport pair', () => {
  it('delivers frames both ways, in order', async () => {
    const [a, b] = createMemoryTransportPair();
    const got: string[] = [];
    b.onMessage((d) => got.push(d));
    a.send(encode({ t: 'ping', ts: 1 }));
    a.send(encode({ t: 'ping', ts: 2 }));
    await tick();
    expect(got.map((d) => (decode(d) as { ts: number }).ts)).toEqual([1, 2]);
  });

  it('propagates close to the peer and refuses sends after close', async () => {
    const [a, b] = createMemoryTransportPair();
    const onClose = vi.fn();
    b.onClose(onClose);
    a.close();
    await tick();
    expect(a.closed).toBe(true);
    expect(b.closed).toBe(true);
    expect(onClose).toHaveBeenCalledOnce();
    expect(() => a.send('x')).toThrow();
  });
});

function tick(): Promise<void> {
  return new Promise((r) => setTimeout(r, 0));
}
