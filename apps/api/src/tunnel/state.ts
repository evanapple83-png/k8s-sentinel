import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Durable agent identity (issue #11, Phase 2). The reconnect token is minted on
 * first boot and held in memory — fine for tunnel drops, but a container/pod
 * restart would lose it and fall back to the (consumed) install token → reject
 * loop. We persist {clusterId, reconnectToken} to a state dir so the agent can
 * re-register after a restart.
 *
 * Mounted at an emptyDir it survives container restarts; back it with a PVC
 * (chart `persistence.enabled`) to also survive pod reschedules. Read-only model
 * is preserved — this writes to its own mounted volume, never to the cluster.
 */
export interface AgentState {
  clusterId: string;
  reconnectToken: string;
}

const FILE = 'agent-state.json';

/** Read persisted identity, or null if absent/unreadable/malformed. */
export function readAgentState(dir: string): AgentState | null {
  try {
    const raw = readFileSync(join(dir, FILE), 'utf8');
    const o = JSON.parse(raw) as Partial<AgentState>;
    if (o && typeof o.clusterId === 'string' && typeof o.reconnectToken === 'string') {
      return { clusterId: o.clusterId, reconnectToken: o.reconnectToken };
    }
  } catch {
    /* missing / unreadable / bad JSON → treat as no persisted state */
  }
  return null;
}

/** Best-effort persist. Failures are non-fatal: in-memory reconnect still works
 *  for this pod's lifetime. Written 0600 — the token is a credential. */
export function writeAgentState(dir: string, state: AgentState): boolean {
  try {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, FILE), JSON.stringify(state), { mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}
