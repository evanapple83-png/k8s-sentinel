import { readFileSync } from 'node:fs';
import { loadConfig } from '../config.js';
import { connectTunnel } from './connect.js';
import { dialRelay } from './ws-client.js';
import { buildTunnelHandlers } from './service.js';

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
 *   SENTINEL_CLUSTER_NAME    friendly name shown in the UI
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

  log('info', 'agent starting', { url, engine: config.engine, mtls: Boolean(tls.cert) });

  await connectTunnel({
    dial: () => dialRelay({ url, cert: tls.cert, key: tls.key, ca: tls.ca }),
    register: {
      token: process.env.SENTINEL_INSTALL_TOKEN,
      clusterId: process.env.SENTINEL_CLUSTER_ID,
      clusterName: process.env.SENTINEL_CLUSTER_NAME,
      agentVersion,
    },
    handlers,
    log,
    onRegistered: (clusterId) => log('info', 'agent online', { clusterId }),
    running: () => running,
  });
}

function readMaybe(path: string | undefined): Buffer | undefined {
  return path ? readFileSync(path) : undefined;
}
