import { readFileSync } from 'node:fs';
import { loadConfig } from '../config.js';
import { connectTunnel } from './connect.js';
import { dialRelay } from './ws-client.js';
import { buildTunnelHandlers } from './service.js';
import { readAgentState, writeAgentState } from './state.js';

/**
 * `sentinel agent` — run the in-cluster tunnel-client (hybrid mode). Dials the
 * relay OUT (no inbound port), registers with the install token (first boot) or
 * the mTLS client cert (thereafter), and serves control commands over the
 * lifetime of the pod. Read-only + propose-only, exactly like the CLI/SSE paths.
 *
 * Env:
 *   RELAY_URL                wss://relay… (required)
 *   SENTINEL_INSTALL_TOKEN   single-use token, first boot
 *   SENTINEL_CLUSTER_ID      known cluster id, on reconnect
 *   SENTINEL_RECONNECT_TOKEN durable reconnect token (issue #11) — replayed with
 *                            SENTINEL_CLUSTER_ID to survive tunnel drops. Held in
 *                            memory after first boot; set via env to also survive
 *                            a pod restart (Phase 2 persists it for you).
 *   SENTINEL_CLUSTER_NAME    friendly name shown in the UI
 *   SENTINEL_STATE_DIR       writable dir to persist the reconnect identity
 *                            (Phase 2). Survives container restarts on an
 *                            emptyDir; pod reschedules too when PVC-backed.
 *   RELAY_CLIENT_CERT/KEY    mTLS client material (PEM paths)
 *   RELAY_CA                 relay/CA bundle to trust (PEM path)
 */
export async function runAgent(): Promise<void> {
  const url = process.env.RELAY_URL;
  if (!url) {
    console.error('sentinel agent: RELAY_URL is required (wss://relay…)');
    process.exitCode = 1;
    return;
  }

  const config = loadConfig();
  const handlers = buildTunnelHandlers(config);
  const agentVersion = process.env.SENTINEL_AGENT_VERSION ?? '0.1.0';

  const tls = {
    cert: readMaybe(process.env.RELAY_CLIENT_CERT),
    key: readMaybe(process.env.RELAY_CLIENT_KEY),
    ca: readMaybe(process.env.RELAY_CA),
  };

  const log = (level: 'info' | 'warn' | 'error', msg: string, meta?: Record<string, unknown>) =>
    console[level === 'error' ? 'error' : 'log'](
      JSON.stringify({ ts: new Date().toISOString(), level, msg, ...meta }),
    );

  let running = true;
  for (const sig of ['SIGINT', 'SIGTERM'] as const) {
    process.on(sig, () => {
      log('info', 'agent shutting down', { sig });
      running = false;
    });
  }

  // Phase 2 (issue #11): prefer a persisted reconnect identity over the
  // single-use install token, so the agent survives a restart. Env vars are the
  // fallback (first boot, or operator-supplied).
  const stateDir = process.env.SENTINEL_STATE_DIR;
  const persisted = stateDir ? readAgentState(stateDir) : null;
  if (persisted) {
    log('info', 'resuming from persisted identity', { clusterId: persisted.clusterId });
  }

  const register = persisted
    ? { clusterId: persisted.clusterId, reconnectToken: persisted.reconnectToken, agentVersion }
    : {
        token: process.env.SENTINEL_INSTALL_TOKEN,
        clusterId: process.env.SENTINEL_CLUSTER_ID,
        reconnectToken: process.env.SENTINEL_RECONNECT_TOKEN,
        clusterName: process.env.SENTINEL_CLUSTER_NAME,
        agentVersion,
      };

  log('info', 'agent starting', { url, engine: config.engine, mtls: Boolean(tls.cert) });

  await connectTunnel({
    dial: () => dialRelay({ url, cert: tls.cert, key: tls.key, ca: tls.ca }),
    register,
    handlers,
    log,
    onRegistered: (clusterId, reconnectToken) => {
      log('info', 'agent online', { clusterId });
      // First-boot ack carries the durable reconnect token — persist it so a
      // restart re-registers with it instead of the consumed install token.
      if (stateDir && reconnectToken) {
        const ok = writeAgentState(stateDir, { clusterId, reconnectToken });
        log(ok ? 'info' : 'warn', ok ? 'persisted reconnect identity' : 'could not persist identity', {
          stateDir,
        });
      }
    },
    running: () => running,
  });
}

function readMaybe(path: string | undefined): Buffer | undefined {
  return path ? readFileSync(path) : undefined;
}
