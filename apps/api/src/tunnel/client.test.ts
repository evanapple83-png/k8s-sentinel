import { describe, expect, it } from 'vitest';
import {
  createMemoryTransportPair,
  decode,
  encode,
  type Message,
  type PostureSnapshot,
  type Transport,
} from '@k8s-sentinel/relay-protocol';
import { TunnelClient, type TunnelHandlers } from './client.js';

const flush = () => new Promise<void>((r) => setTimeout(r, 0));

function emptySnapshot(runId = 'run-1'): PostureSnapshot {
  return {
    run: {
      id: runId,
      status: 'complete',
      engine: 'claude',
      usedFixtures: true,
      findingCount: 0,
      pathCount: 0,
      riskScore: 10,
      summary: 'ok',
      startedAt: '2026-05-27T00:00:00.000Z',
      finishedAt: '2026-05-27T00:01:00.000Z',
    },
    findings: [],
    paths: [],
    remediations: [],
    audit: [],
  };
}

/** A fake relay side: collects what the client sends, lets the test push frames. */
class FakeRelay {
  readonly got: Message[] = [];
  constructor(private readonly side: Transport) {
    side.onMessage((d) => this.got.push(decode(d)));
  }
  push(msg: Message): void {
    this.side.send(encode(msg));
  }
  close(): void {
    this.side.close();
  }
  ofType<T extends Message['t']>(t: T): Extract<Message, { t: T }>[] {
    return this.got.filter((m): m is Extract<Message, { t: T }> => m.t === t);
  }
}

function setup(handlers: Partial<TunnelHandlers> = {}) {
  const [relaySide, clientSide] = createMemoryTransportPair();
  const relay = new FakeRelay(relaySide);
  const full: TunnelHandlers = {
    scan: async (_p, emit) => {
      emit({ type: 'message', text: 'collecting…' });
      emit({ type: 'message', text: 'correlating…' });
      return emptySnapshot();
    },
    ask: async (q) => ({ answer: `re: ${q}` }),
    approve: async (fixId) => ({ approved: fixId, branch: `sentinel/${fixId}` }),
    report: async (format) => ({ format, bytes: 1234 }),
    ...handlers,
  };
  const client = new TunnelClient({ transport: clientSide, register: { token: 'sk-install-x' }, handlers: full });
  return { relay, client };
}

describe('TunnelClient registration', () => {
  it('sends register on start and resolves with the relay-assigned clusterId', async () => {
    const { relay, client } = setup();
    const started = client.start();
    await flush();
    expect(relay.ofType('register')[0]).toMatchObject({ protocol: 1, token: 'sk-install-x' });

    relay.push({ t: 'registered', clusterId: 'cluster-7', sessionId: 's1' });
    await expect(started).resolves.toBe('cluster-7');
  });

  it('rejects start() if the transport closes before registration', async () => {
    const { relay, client } = setup();
    const started = client.start();
    await flush();
    relay.close();
    await expect(started).rejects.toThrow(/closed before registration/);
  });

  it('answers relay pings with a pong', async () => {
    const { relay, client } = setup();
    void client.start();
    relay.push({ t: 'ping', ts: 99 });
    await flush();
    expect(relay.ofType('pong')[0]?.ts).toBe(99);
  });
});

describe('TunnelClient commands', () => {
  async function registered(handlers?: Partial<TunnelHandlers>) {
    const ctx = setup(handlers);
    const started = ctx.client.start();
    await flush();
    ctx.relay.push({ t: 'registered', clusterId: 'cluster-7', sessionId: 's1' });
    await started;
    return ctx;
  }

  it('acks, streams events, then pushes a snapshot + result for a scan command', async () => {
    const { relay } = await registered();
    relay.push({ t: 'command', id: 'cmd-1', clusterId: 'cluster-7', kind: 'scan' });
    await flush();

    expect(relay.ofType('ack')[0]?.id).toBe('cmd-1');
    expect(relay.ofType('event').map((e) => e.event.text)).toEqual(['collecting…', 'correlating…']);
    expect(relay.ofType('snapshot')[0]?.snapshot.run.id).toBe('run-1');
    expect(relay.ofType('result')[0]).toEqual({ t: 'result', id: 'cmd-1', ok: true, data: { runId: 'run-1' } });
  });

  it('returns the answer for an ask command', async () => {
    const { relay } = await registered();
    relay.push({ t: 'command', id: 'cmd-2', clusterId: 'cluster-7', kind: 'ask', params: { query: 'what is exposed?' } });
    await flush();
    expect(relay.ofType('result')[0]).toEqual({
      t: 'result',
      id: 'cmd-2',
      ok: true,
      data: { answer: 're: what is exposed?' },
    });
  });

  it('returns the PR-bundle metadata for an approve command', async () => {
    const { relay } = await registered();
    relay.push({ t: 'command', id: 'cmd-3', clusterId: 'cluster-7', kind: 'approve', params: { fixId: 'fix-9' } });
    await flush();
    expect(relay.ofType('result')[0]?.data).toEqual({ approved: 'fix-9', branch: 'sentinel/fix-9' });
  });

  it('reports a failing handler as result.ok = false, without crashing the tunnel', async () => {
    const { relay, client } = await registered({
      ask: async () => {
        throw new Error('store unavailable');
      },
    });
    relay.push({ t: 'command', id: 'cmd-4', clusterId: 'cluster-7', kind: 'ask', params: { query: 'x' } });
    await flush();
    expect(relay.ofType('result')[0]).toEqual({ t: 'result', id: 'cmd-4', ok: false, error: 'store unavailable' });
    // Tunnel still alive: a follow-up command is still serviced.
    relay.push({ t: 'command', id: 'cmd-5', clusterId: 'cluster-7', kind: 'report', params: { format: 'md' } });
    await flush();
    expect(relay.ofType('result')[1]).toMatchObject({ id: 'cmd-5', ok: true });
  });
});
