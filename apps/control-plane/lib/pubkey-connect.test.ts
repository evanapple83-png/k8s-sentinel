import { describe, expect, it } from 'vitest';
import {
  constantTimeEqual,
  hashToken,
  projectToClusterColumn,
  reduceStatus,
  sanitizeEventDetail,
  type ConnectionEventType,
  type ExtendedClusterStatus,
} from './pubkey-connect';

/**
 * Unit tests for the pure pieces of the pubkey-connect data layer.
 *
 * These functions live behind the public API of pubkey-connect.ts but are
 * exported (and tested) directly because they encode the wire contract:
 *
 *   - reduceStatus       : event → status mapping per CONTRACT §2
 *   - projectToClusterColumn : extended → narrow legacy enum (so the existing
 *                          dashboard keeps rendering without a schema migration)
 *   - constantTimeEqual  : timing-safe string compare for token verification
 *   - hashToken          : sha256 hex digest (the only persisted form of the
 *                          enrollment token)
 *   - sanitizeEventDetail: 2 KB body cap per contract §2
 *
 * Anything that touches Supabase (createClusterEnrollment, recordConnectionEvent,
 * ingestPubkeyScan) is integration-tested by running the API routes end-to-end
 * — covered by the kind-cluster smoke test in the build spec §8 step 5.
 */

describe('reduceStatus', () => {
  // CONTRACT §2 ground-truth table.
  it('maps each event to the right next status from pending', () => {
    expect(reduceStatus('pending', 'agent_registered')).toBe('connected');
    expect(reduceStatus('pending', 'cli_started')).toBe('cli_started');
    expect(reduceStatus('pending', 'csr_submitted')).toBe('csr_submitted');
    expect(reduceStatus('pending', 'awaiting_approval')).toBe('awaiting_approval');
    expect(reduceStatus('pending', 'approved')).toBe('approved');
    expect(reduceStatus('pending', 'rbac_bound')).toBe('approved');
    expect(reduceStatus('pending', 'scan_pushed')).toBe('connected');
    expect(reduceStatus('pending', 'error')).toBe('failed');
  });

  it('keeps connected sticky against any later event', () => {
    const ev: ConnectionEventType[] = [
      'agent_registered',
      'cli_started',
      'csr_submitted',
      'awaiting_approval',
      'approved',
      'rbac_bound',
      'scan_pushed',
      'error', // critically: an error after connected must NOT downgrade
    ];
    for (const e of ev) {
      expect(reduceStatus('connected', e)).toBe('connected');
    }
  });

  it('walks the happy pubkey path deterministically', () => {
    const happy: ConnectionEventType[] = [
      'cli_started',
      'csr_submitted',
      'awaiting_approval',
      'approved',
      'rbac_bound',
      'scan_pushed',
    ];
    let s: ExtendedClusterStatus = 'pending';
    const trail: ExtendedClusterStatus[] = [];
    for (const e of happy) {
      s = reduceStatus(s, e);
      trail.push(s);
    }
    expect(trail).toEqual([
      'cli_started',
      'csr_submitted',
      'awaiting_approval',
      'approved',
      'approved', // rbac_bound also resolves to 'approved'
      'connected',
    ]);
  });

  it('treats helm registration as a direct jump to connected', () => {
    expect(reduceStatus('pending', 'agent_registered')).toBe('connected');
  });
});

describe('projectToClusterColumn', () => {
  it('maps the extended states onto the narrow legacy enum', () => {
    expect(projectToClusterColumn('pending')).toBe('pending');
    expect(projectToClusterColumn('cli_started')).toBe('pending');
    expect(projectToClusterColumn('csr_submitted')).toBe('pending');
    expect(projectToClusterColumn('awaiting_approval')).toBe('pending');
    expect(projectToClusterColumn('approved')).toBe('pending');
    expect(projectToClusterColumn('connected')).toBe('connected');
    expect(projectToClusterColumn('failed')).toBe('disconnected');
    expect(projectToClusterColumn('expired')).toBe('disconnected');
    expect(projectToClusterColumn('disconnected')).toBe('disconnected');
  });
});

describe('constantTimeEqual', () => {
  it('returns true for identical strings', () => {
    expect(constantTimeEqual('ent_abc', 'ent_abc')).toBe(true);
    expect(constantTimeEqual('', '')).toBe(true);
  });

  it('returns false for different strings of equal length', () => {
    expect(constantTimeEqual('ent_abc', 'ent_abd')).toBe(false);
  });

  it('returns false for length mismatches without throwing', () => {
    // Underlying timingSafeEqual throws on unequal lengths; we short-circuit.
    expect(constantTimeEqual('a', 'ab')).toBe(false);
    expect(constantTimeEqual('ent_abc', 'ent_abcdef')).toBe(false);
  });

  it('returns false when either input is not a string', () => {
    // Defensive: callers might forward a typed-as-string field that happens to
    // be undefined; we must not throw.
    expect(constantTimeEqual(undefined as unknown as string, 'x')).toBe(false);
    expect(constantTimeEqual('x', null as unknown as string)).toBe(false);
  });
});

describe('hashToken', () => {
  it('produces a stable sha256 hex (64 chars) for a given input', () => {
    const h = hashToken('ent_test');
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken('ent_test')).toBe(h); // deterministic
  });

  it('produces different hashes for different inputs', () => {
    expect(hashToken('ent_a')).not.toBe(hashToken('ent_b'));
  });
});

describe('sanitizeEventDetail', () => {
  it('passes through small payloads verbatim', () => {
    const d = { csrName: 'argus-agent-abc', ttlSeconds: 3600 };
    expect(sanitizeEventDetail(d)).toBe(d);
  });

  it('throws on payloads over 2 KB', () => {
    // 2050 bytes of JSON when stringified.
    const big = { blob: 'x'.repeat(2050) };
    expect(() => sanitizeEventDetail(big)).toThrowError(/too large/);
  });

  it('throws on circular structures (not JSON-serializable)', () => {
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    expect(() => sanitizeEventDetail(cycle)).toThrowError();
  });
});
