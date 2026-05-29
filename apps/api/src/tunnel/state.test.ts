import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { readAgentState, writeAgentState } from './state.js';

describe('agent state persistence (issue #11 Phase 2)', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sentinel-state-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('round-trips clusterId + reconnectToken', () => {
    expect(writeAgentState(dir, { clusterId: 'c1', reconnectToken: 'sk-reconnect-abc' })).toBe(true);
    expect(readAgentState(dir)).toEqual({ clusterId: 'c1', reconnectToken: 'sk-reconnect-abc' });
  });

  it('returns null when no state file exists', () => {
    expect(readAgentState(dir)).toBeNull();
  });

  it('returns null for malformed / incomplete state', () => {
    writeFileSync(join(dir, 'agent-state.json'), '{ not json');
    expect(readAgentState(dir)).toBeNull();
    writeFileSync(join(dir, 'agent-state.json'), JSON.stringify({ clusterId: 'c1' }));
    expect(readAgentState(dir)).toBeNull();
  });

  it('creates the dir if missing and writes 0600', () => {
    const nested = join(dir, 'a', 'b');
    expect(writeAgentState(nested, { clusterId: 'c2', reconnectToken: 't2' })).toBe(true);
    expect(readAgentState(nested)).toEqual({ clusterId: 'c2', reconnectToken: 't2' });
  });
});
