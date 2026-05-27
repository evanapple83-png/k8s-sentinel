import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createMemoryTransportPair,
  decode,
  encode,
  type Message,
  type Transport,
} from '@k8s-sentinel/relay-protocol';
import { Relay, type ConnContext, type RelayDeps } from './relay.js';

/** A driven client: send typed frames, read decoded frames back. */
class Client {
  readonly frames: Message[] = [];
  constructor(private readonly transport: Transport) {
    transport.onMessage((d) => this.frames.push(decode(d)));
  }
  send(msg: Message): void {
    this.transport.send(encode(msg));
  }
  get closed(): boolean {
    return this.transport.closed;
  }
  last(): Message | undefined {
    return this.frames.at(-1);
  }
  ofType<T extends Message['t']>(t: T): Extract<Message, { t: T }>[] {
    return this.frames.filter((f): f is Extract<Message, { t: T }> => f.t === t);
  }
}

function connect(relay: Relay, ctx: ConnContext = {}): Client {
  const [relaySide, clientSide] = createMemoryTransportPair();
  relay.accept(relaySide, ctx);
  return new Client(clientSide);
}

/** Drain all pending microtasks (memory transport delivers on microtasks). */
const flush = () => new Promise<void>((r) => setTimeout(r, 0));

function makeRelay(over: Partial<RelayDeps> = {}): Relay {
  let seq = 0;
  return new Relay({
    // token "ok-<cluster>" authenticates to that cluster; anything else throws.
    verifyAgent: async (reg) => {
      const m = /^ok-(.+)$/.exec(reg.token ?? '');
      if (!m) throw new Error('bad token');
      return { clusterId: m[1]! };
    },
    // control must present authToken === "trusted".
    authorizeControl: async (_sub, ctx) => {
      if (ctx.authToken !== 'trusted') throw new Error('forbidden');
    },
    now: () => 1_000_000, // frozen clock; overridden per-test where needed
    genId: () => `sess-${seq++}`,
    ...over,
  });
}

describe('relay identity', () => {
  let relay: Relay;
  beforeEach(() => {
    relay = makeRelay();
  });

  it('registers an agent and resolves its clusterId from the token', async () => {
    const agent = connect(relay);
    agent.send({ t: 'register', protocol: 1, token: 'ok-cluster-a' });
    await flush();
    expect(agent.last()).toEqual({ t: 'registered', clusterId: 'cluster-a', sessionId: 'sess-0' });
    expect(relay.stats().agents).toBe(1);
  });

  it('subscribes an authorized control', async () => {
    const control = connect(relay, { authToken: 'trusted' });
    control.send({ t: 'subscribe', clusterId: 'cluster-a' });
    await flush();
    expect(control.last()).toEqual({ t: 'subscribed', clusterId: 'cluster-a' });
  });

  it('rejects and closes an agent with a bad token', async () => {
    const agent = connect(relay);
    agent.send({ t: 'register', protocol: 1, token: 'nope' });
    await flush();
    expect(agent.ofType('error')[0]?.code).toBe('unauthorized');
    expect(agent.closed).toBe(true);
    expect(relay.stats().agents).toBe(0);
  });

  it('rejects an unauthorized control subscription', async () => {
    const control = connect(relay, { authToken: 'guessed' });
    control.send({ t: 'subscribe', clusterId: 'cluster-a' });
    await flush();
    expect(control.ofType('error')[0]?.code).toBe('unauthorized');
    expect(control.closed).toBe(true);
  });

  it('rejects a protocol-version mismatch', async () => {
    const agent = connect(relay);
    agent.send({ t: 'register', protocol: 999, token: 'ok-cluster-a' });
    await flush();
    expect(agent.ofType('error')[0]?.code).toBe('protocol_mismatch');
    expect(agent.closed).toBe(true);
  });

  it('requires identification before any other frame', async () => {
    const peer = connect(relay);
    peer.send({ t: 'command', id: 'c1', clusterId: 'cluster-a', kind: 'scan' });
    await flush();
    expect(peer.ofType('error')[0]?.code).toBe('not_identified');
  });

  it('lets the newest agent supersede an older one for the same cluster', async () => {
    const a1 = connect(relay);
    a1.send({ t: 'register', protocol: 1, token: 'ok-cluster-a' });
    await flush();
    const a2 = connect(relay);
    a2.send({ t: 'register', protocol: 1, token: 'ok-cluster-a' });
    await flush();
    expect(a1.ofType('bye')[0]?.reason).toContain('superseded');
    expect(a1.closed).toBe(true);
    expect(relay.stats().agents).toBe(1);
  });
});

describe('relay routing', () => {
  let relay: Relay;
  beforeEach(() => {
    relay = makeRelay();
  });

  async function pair(cluster: string): Promise<{ agent: Client; control: Client }> {
    const agent = connect(relay);
    agent.send({ t: 'register', protocol: 1, token: `ok-${cluster}` });
    const control = connect(relay, { authToken: 'trusted' });
    control.send({ t: 'subscribe', clusterId: cluster });
    await flush();
    return { agent, control };
  }

  it('forwards a command from control to the cluster agent, stamped with the cluster id', async () => {
    const { agent, control } = await pair('cluster-a');
    control.send({ t: 'command', id: 'cmd-1', clusterId: 'cluster-a', kind: 'scan' });
    await flush();
    const cmd = agent.ofType('command')[0];
    expect(cmd).toMatchObject({ id: 'cmd-1', clusterId: 'cluster-a', kind: 'scan' });
  });

  it('forwards an agent snapshot to the subscribed control, re-stamping a spoofed cluster id', async () => {
    const { agent, control } = await pair('cluster-a');
    // Agent lies, claiming another tenant's cluster id.
    agent.send({
      t: 'snapshot',
      clusterId: 'victim-cluster',
      snapshot: {
        run: {
          id: 'run-1',
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
      },
    });
    await flush();
    const snap = control.ofType('snapshot')[0];
    expect(snap?.clusterId).toBe('cluster-a'); // bound id wins, not the spoof
  });

  it('tells the control when the target agent is offline', async () => {
    const control = connect(relay, { authToken: 'trusted' });
    control.send({ t: 'subscribe', clusterId: 'cluster-a' });
    await flush();
    control.send({ t: 'command', id: 'cmd-x', clusterId: 'cluster-a', kind: 'scan' });
    await flush();
    expect(control.ofType('result')[0]).toEqual({ t: 'result', id: 'cmd-x', ok: false, error: 'agent offline' });
  });

  it('does not deliver one cluster’s frames to another cluster’s control', async () => {
    const { agent: agentA } = await pair('cluster-a');
    const controlB = connect(relay, { authToken: 'trusted' });
    controlB.send({ t: 'subscribe', clusterId: 'cluster-b' });
    await flush();
    agentA.send({ t: 'event', clusterId: 'cluster-a', event: { type: 'message', text: 'hi' } });
    await flush();
    expect(controlB.ofType('event')).toHaveLength(0);
  });

  it('answers a ping with a pong on either role', async () => {
    const { agent, control } = await pair('cluster-a');
    agent.send({ t: 'ping', ts: 42 });
    control.send({ t: 'ping', ts: 43 });
    await flush();
    expect(agent.ofType('pong')[0]?.ts).toBe(42);
    expect(control.ofType('pong')[0]?.ts).toBe(43);
  });

  it('cleans up registries when connections close', async () => {
    const { agent, control } = await pair('cluster-a');
    expect(relay.stats()).toMatchObject({ agents: 1, controlConnections: 1 });
    // `bye` makes the relay close the connection; its onClose evicts from the registries.
    agent.send({ t: 'bye' });
    control.send({ t: 'bye' });
    await flush();
    expect(relay.stats()).toMatchObject({ agents: 0, controlConnections: 0 });
  });
});

describe('relay liveness', () => {
  it('sweeps connections idle past the cutoff', async () => {
    let clock = 1000;
    const relay = makeRelay({ now: () => clock });
    const agent = connect(relay);
    agent.send({ t: 'register', protocol: 1, token: 'ok-cluster-a' });
    await flush();
    clock += 60_000; // 60s later
    const evicted = relay.sweep(30_000); // evict anything idle > 30s
    await flush();
    expect(evicted).toBe(1);
    expect(agent.ofType('bye')[0]?.reason).toContain('idle');
    expect(relay.stats().agents).toBe(0);
  });
});

describe('relay command RPC + ingest hook', () => {
  const sampleSnapshot = {
    run: {
      id: 'run-1',
      status: 'complete' as const,
      engine: 'claude',
      usedFixtures: true,
      findingCount: 0,
      pathCount: 0,
      riskScore: 5,
      summary: null,
      startedAt: '2026-05-27T00:00:00.000Z',
    },
    findings: [],
    paths: [],
    remediations: [],
    audit: [],
  };

  it('bridges sendCommand → agent → result (HTTP-style RPC)', async () => {
    const relay = makeRelay();
    const agent = connect(relay);
    agent.send({ t: 'register', protocol: 1, token: 'ok-cluster-a' });
    await flush();

    const promise = relay.sendCommand('cluster-a', 'scan', undefined, 1000);
    await flush();
    const cmd = agent.ofType('command').at(-1)!;
    agent.send({ t: 'result', id: cmd.id, ok: true, data: { runId: 'run-9' } });

    await expect(promise).resolves.toMatchObject({ ok: true, data: { runId: 'run-9' } });
  });

  it('resolves sendCommand with ok:false when the agent is offline', async () => {
    const relay = makeRelay();
    await expect(relay.sendCommand('ghost', 'scan', undefined)).resolves.toMatchObject({
      ok: false,
      error: 'agent offline',
    });
  });

  it('invokes the onSnapshot ingest hook with the bound cluster id', async () => {
    const onSnapshot = vi.fn();
    const relay = makeRelay({ onSnapshot });
    const agent = connect(relay);
    agent.send({ t: 'register', protocol: 1, token: 'ok-cluster-a' });
    await flush();

    agent.send({ t: 'snapshot', clusterId: 'spoofed', snapshot: sampleSnapshot });
    await flush();

    expect(onSnapshot).toHaveBeenCalledTimes(1);
    expect(onSnapshot.mock.calls[0]![0]).toBe('cluster-a'); // bound id, not 'spoofed'
    expect(onSnapshot.mock.calls[0]![1]).toMatchObject({ run: { id: 'run-1' } });
  });
});

describe('relay codec safety', () => {
  it('returns a protocol error for a malformed inbound frame, without crashing', async () => {
    const relay = makeRelay();
    const [relaySide, clientSide] = createMemoryTransportPair();
    relay.accept(relaySide);
    const got: Message[] = [];
    clientSide.onMessage((d) => got.push(decode(d)));
    clientSide.send('}{ not json');
    await flush();
    expect(got[0]).toMatchObject({ t: 'error', code: 'bad_json' });
    expect(clientSide.closed).toBe(false); // a bad frame doesn't kill the connection
  });
});
