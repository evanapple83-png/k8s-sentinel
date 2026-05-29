import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { readFileSync } from 'node:fs';
import type { TLSSocket } from 'node:tls';
import { WebSocketServer, type WebSocket } from 'ws';
import { PROTOCOL_VERSION, type RegisterMsg, type SubscribeMsg } from '@k8s-sentinel/relay-protocol';
import { Relay, type ConnContext } from './relay.js';
import { wsTransport } from './ws-transport.js';

/**
 * Relay server entrypoint (deploys to Fly.io — see fly.toml). Terminates the
 * agent's outbound mTLS tunnel and the control plane's authenticated socket,
 * then hands each connection to the stateless {@link Relay}. Holds no payloads.
 *
 * Auth wiring (all env-driven):
 *  - Agents: if a client cert was validated (mTLS), its CN is the clusterId.
 *    Otherwise (bootstrap / dev) the install token is exchanged with the control
 *    plane's /api/agent/register to resolve the clusterId.
 *  - Controls: must present `Authorization: Bearer <RELAY_CONTROL_SECRET>`.
 */

const PORT = Number(process.env.PORT ?? (hasTls() ? 8443 : 8080));
const CONTROL_SECRET = process.env.RELAY_CONTROL_SECRET ?? '';
const CONTROL_PLANE_URL = (process.env.CONTROL_PLANE_URL ?? '').replace(/\/+$/, '');
const INGEST_SECRET = process.env.RELAY_INGEST_SECRET ?? '';
const IDLE_MS = Number(process.env.RELAY_IDLE_MS ?? 60_000);

/** ws socket tagged with heartbeat liveness (F16). */
type HeartbeatWs = WebSocket & { isAlive?: boolean };

const log = (level: 'info' | 'warn' | 'error', msg: string, meta?: Record<string, unknown>) =>
  console[level === 'error' ? 'error' : 'log'](
    JSON.stringify({ ts: new Date().toISOString(), level, msg, ...meta }),
  );

const relay = new Relay({
  verifyAgent,
  authorizeControl,
  onSnapshot: ingestToControlPlane,
  onAgentDisconnect: notifyDisconnect,
  log,
});

/**
 * Durable ingest: forward each posture push to the hosted control plane's HTTP
 * webhook. The relay persists nothing locally — it relays the payload onward,
 * authenticated by a shared secret. No-op when no control plane is configured.
 */
/**
 * Tell the control plane an agent's tunnel dropped so it flips cluster.status to
 * disconnected (no ghost "connected" clusters that scans would target). Shares
 * the ingest secret. Best-effort — a missed notify self-corrects on reconnect
 * (register re-marks connected) or the next disconnect. (F1)
 */
async function notifyDisconnect(clusterId: string): Promise<void> {
  if (!CONTROL_PLANE_URL || !INGEST_SECRET) return;
  try {
    await fetch(`${CONTROL_PLANE_URL}/api/agent/disconnect`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${INGEST_SECRET}` },
      body: JSON.stringify({ clusterId }),
    });
  } catch (e) {
    log('warn', 'disconnect notify failed', { err: String(e), clusterId });
  }
}

async function ingestToControlPlane(clusterId: string, snapshot: unknown): Promise<void> {
  if (!CONTROL_PLANE_URL || !INGEST_SECRET) return;
  const res = await fetch(`${CONTROL_PLANE_URL}/api/agent/ingest`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${INGEST_SECRET}` },
    body: JSON.stringify({ clusterId, snapshot }),
  });
  if (!res.ok) throw new Error(`ingest webhook returned ${res.status}`);
}

/**
 * Resolve an agent to its clusterId. mTLS cert (CN) is authoritative; the token
 * path is the first-boot bootstrap that exchanges the install token upstream.
 */
async function verifyAgent(reg: RegisterMsg, ctx: ConnContext): Promise<{ clusterId: string; reconnectToken?: string }> {
  if (ctx.certCommonName) return { clusterId: ctx.certCommonName };

  // Token paths (issue #11): a durable reconnect token (replayable) takes
  // precedence over the single-use install token. Both are validated upstream.
  const hasReconnect = Boolean(reg.reconnectToken && reg.clusterId);
  if ((hasReconnect || reg.token) && CONTROL_PLANE_URL) {
    const res = await fetch(`${CONTROL_PLANE_URL}/api/agent/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(
        hasReconnect
          ? { clusterId: reg.clusterId, reconnectToken: reg.reconnectToken, agentVersion: reg.agentVersion }
          : { token: reg.token, agentVersion: reg.agentVersion, clusterName: reg.clusterName },
      ),
    });
    if (!res.ok) throw new Error(`control-plane register returned ${res.status}`);
    const body = (await res.json()) as { clusterId?: string; reconnectToken?: string };
    if (!body.clusterId) throw new Error('control-plane register returned no clusterId');
    // reconnectToken is present only on the first-boot exchange; pass it through
    // so the relay can hand it to the agent in the `registered` ack.
    return { clusterId: body.clusterId, reconnectToken: body.reconnectToken };
  }
  throw new Error('no client cert and no token/control-plane configured');
}

async function authorizeControl(_sub: SubscribeMsg, ctx: ConnContext): Promise<void> {
  if (!CONTROL_SECRET) throw new Error('RELAY_CONTROL_SECRET not configured; refusing control connections');
  if (ctx.authToken !== CONTROL_SECRET) throw new Error('bad control secret');
}

// --- HTTP(S) + WebSocket plumbing -------------------------------------------

function hasTls(): boolean {
  return Boolean(process.env.RELAY_TLS_CERT && process.env.RELAY_TLS_KEY);
}

function handleHttp(req: IncomingMessage, res: ServerResponse): void {
  if ((req.method ?? 'GET') === 'GET' && (req.url === '/healthz' || req.url === '/')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, protocol: PROTOCOL_VERSION, ...relay.stats() }));
    return;
  }
  // HTTP command bridge: the hosted plane drives a cluster without holding a WS.
  if (req.method === 'POST' && (req.url ?? '').split('?')[0] === '/command') {
    void handleCommand(req, res);
    return;
  }
  res.writeHead(404).end();
}

async function handleCommand(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const sendJson = (status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  const auth = req.headers['authorization'];
  if (!CONTROL_SECRET || auth !== `Bearer ${CONTROL_SECRET}`) return sendJson(401, { error: 'unauthorized' });

  let raw = '';
  let tooBig = false;
  req.on('data', (c) => {
    raw += c;
    if (raw.length > 1_000_000) tooBig = true; // commands are tiny
  });
  req.on('end', () => {
    void (async () => {
      if (tooBig) return sendJson(413, { error: 'body too large' });
      let body: { clusterId?: unknown; kind?: unknown; params?: unknown };
      try {
        body = JSON.parse(raw || '{}');
      } catch {
        return sendJson(400, { error: 'invalid JSON' });
      }
      const clusterId = typeof body.clusterId === 'string' ? body.clusterId : '';
      const kind = body.kind;
      if (!clusterId || (kind !== 'scan' && kind !== 'ask' && kind !== 'approve' && kind !== 'report')) {
        return sendJson(400, { error: 'clusterId and a valid kind are required' });
      }
      // HA (F7): the agent's WS tunnel lives on exactly one machine, but Fly
      // load-balances this POST across all of them. If the agent isn't on THIS
      // machine, ask Fly to replay the request elsewhere — the machine holding
      // the tunnel will handle it. `fly-replay-src` is set by Fly on a replayed
      // request, so we bounce at most once (optimal for 2 machines; a shared
      // backplane would be needed for >2). A genuinely offline agent falls
      // through to sendCommand → "agent offline".
      if (!relay.hasAgent(clusterId) && !req.headers['fly-replay-src']) {
        res.writeHead(202, { 'fly-replay': 'elsewhere=true' });
        res.end();
        return;
      }
      const params = body.params && typeof body.params === 'object' ? (body.params as Record<string, unknown>) : undefined;
      const result = await relay.sendCommand(clusterId, kind, params);
      sendJson(result.ok ? 200 : 502, result);
    })();
  });
}

const server = hasTls()
  ? createHttpsServer(
      {
        cert: readFileSync(process.env.RELAY_TLS_CERT!),
        key: readFileSync(process.env.RELAY_TLS_KEY!),
        // mTLS: request a client cert and verify it against our CA when present.
        // requestCert without rejectUnauthorized lets the token-bootstrap path
        // (first boot, no cert yet) still connect; certed agents are validated.
        ca: process.env.RELAY_CLIENT_CA ? readFileSync(process.env.RELAY_CLIENT_CA) : undefined,
        requestCert: Boolean(process.env.RELAY_CLIENT_CA),
        rejectUnauthorized: false,
      },
      handleHttp,
    )
  : createHttpServer(handleHttp);

const wss = new WebSocketServer({ server, maxPayload: 8 * 1024 * 1024 });

wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
  // F16: TCP-level liveness. A half-open socket (Fly edge drop, network blip)
  // is invisible to the app protocol — pings stop arriving but the socket lingers
  // until the idle sweep (~minute+), during which a command routed to it HANGS to
  // the 120s timeout. The heartbeat below terminates such sockets within ~30s so
  // the relay's agent registry stays accurate and dead clusters fail fast.
  (ws as HeartbeatWs).isAlive = true;
  ws.on('pong', () => {
    (ws as HeartbeatWs).isAlive = true;
  });

  const ctx: ConnContext = { remote: req.socket.remoteAddress ?? undefined };

  // Control plane presents a bearer; agents send their token in the register frame.
  const auth = req.headers['authorization'];
  if (typeof auth === 'string' && auth.startsWith('Bearer ')) ctx.authToken = auth.slice(7);

  // Pull the validated mTLS client cert, if any.
  const sock = req.socket as TLSSocket;
  if (typeof sock.getPeerCertificate === 'function' && sock.authorized) {
    const cert = sock.getPeerCertificate();
    if (cert && cert.subject) {
      const cn = cert.subject.CN as string | string[] | undefined;
      ctx.certCommonName = Array.isArray(cn) ? cn[0] : cn;
      ctx.certFingerprint = cert.fingerprint256;
    }
  }

  relay.accept(wsTransport(ws), ctx);
});

// Liveness (app-level backstop): evict connections idle past IDLE_MS.
const sweepTimer = setInterval(() => {
  const evicted = relay.sweep(IDLE_MS);
  if (evicted) log('info', 'swept idle connections', { evicted, ...relay.stats() });
}, Math.max(15_000, Math.floor(IDLE_MS / 3)));
sweepTimer.unref?.();

// F16: TCP-level heartbeat. Ping every HEARTBEAT_MS; a socket that misses two
// rounds (no pong) is half-open → terminate it (fires 'close' → relay evicts the
// agent + flips cluster.status via onAgentDisconnect). Far faster than the idle
// sweep, so commands never route to a dead socket and hang.
const HEARTBEAT_MS = Number(process.env.RELAY_HEARTBEAT_MS ?? 15_000);
const heartbeatTimer = setInterval(() => {
  for (const client of wss.clients) {
    const ws = client as HeartbeatWs;
    if (ws.isAlive === false) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    try {
      ws.ping();
    } catch {
      /* socket already going away */
    }
  }
}, HEARTBEAT_MS);
heartbeatTimer.unref?.();

server.listen(PORT, () => {
  log('info', 'relay listening', { port: PORT, tls: hasTls(), mtls: Boolean(process.env.RELAY_CLIENT_CA) });
});

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, () => {
    log('info', 'shutting down', { sig });
    clearInterval(sweepTimer);
    clearInterval(heartbeatTimer);
    wss.close();
    server.close(() => process.exit(0));
  });
}
