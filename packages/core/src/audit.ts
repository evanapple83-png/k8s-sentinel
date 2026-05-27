import { z } from 'zod';

/**
 * Immutable audit trail. Every agent decision, tool call, and command lands
 * here. Entries are append-only and hash-chained so tampering is detectable.
 */

export const AuditEntrySchema = z.object({
  /** Monotonic sequence within a run/store. */
  seq: z.number().int().nonnegative(),
  ts: z.string().datetime(),
  actor: z.enum(['agent', 'user', 'orchestrator', 'system']),
  /** Which agent, when actor === "agent". */
  agent: z.enum(['collector', 'analyst', 'author']).optional(),
  /** Logical action, e.g. "scan.start", "tool.call", "report.export". */
  action: z.string(),
  tool: z.string().optional(),
  input: z.unknown().optional(),
  output: z.unknown().optional(),
  /** Correlation id for the run this entry belongs to. */
  runId: z.string().optional(),
  /** Hash of the previous entry (chain integrity). Empty for the genesis entry. */
  prevHash: z.string().default(''),
  /** Hash of this entry's canonical content. */
  hash: z.string(),
});
export type AuditEntry = z.infer<typeof AuditEntrySchema>;

export type AuditDraft = Omit<AuditEntry, 'seq' | 'ts' | 'prevHash' | 'hash'> &
  Partial<Pick<AuditEntry, 'ts'>>;

export interface AuditSink {
  /** Append one entry, returning the persisted (sealed) entry. */
  append(draft: AuditDraft): Promise<AuditEntry>;
  /** Read entries, optionally scoped to a run. */
  list(runId?: string): Promise<AuditEntry[]>;
  /** Verify the hash chain is intact. */
  verify(): Promise<{ ok: boolean; brokenAt?: number }>;
}
