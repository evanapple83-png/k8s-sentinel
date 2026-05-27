import { createHash } from 'node:crypto';
import { appendFile, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import type { AuditDraft, AuditEntry, AuditSink } from './audit.js';

/** Canonical content hash for one entry (excludes its own hash field). */
function hashEntry(entry: Omit<AuditEntry, 'hash'>): string {
  const canonical = JSON.stringify({
    seq: entry.seq,
    ts: entry.ts,
    actor: entry.actor,
    agent: entry.agent ?? null,
    action: entry.action,
    tool: entry.tool ?? null,
    input: entry.input ?? null,
    output: entry.output ?? null,
    runId: entry.runId ?? null,
    prevHash: entry.prevHash,
  });
  return createHash('sha256').update(canonical).digest('hex');
}

function seal(draft: AuditDraft, seq: number, prevHash: string): AuditEntry {
  const base: Omit<AuditEntry, 'hash'> = {
    seq,
    ts: draft.ts ?? new Date().toISOString(),
    actor: draft.actor,
    agent: draft.agent,
    action: draft.action,
    tool: draft.tool,
    input: draft.input,
    output: draft.output,
    runId: draft.runId,
    prevHash,
  };
  return { ...base, hash: hashEntry(base) };
}

/**
 * Append-only, hash-chained audit sink. Holds entries in memory and (optionally)
 * mirrors them to a JSONL file so the log survives restarts. Tampering with any
 * entry breaks the chain, which `verify()` detects.
 */
export class FileAuditSink implements AuditSink {
  private entries: AuditEntry[] = [];
  private loaded = false;

  constructor(private readonly filePath?: string) {}

  private async ensureLoaded(): Promise<void> {
    if (this.loaded) return;
    this.loaded = true;
    if (this.filePath && existsSync(this.filePath)) {
      const raw = await readFile(this.filePath, 'utf8');
      this.entries = raw
        .split('\n')
        .filter((l) => l.trim().length > 0)
        .map((l) => JSON.parse(l) as AuditEntry);
    }
  }

  async append(draft: AuditDraft): Promise<AuditEntry> {
    await this.ensureLoaded();
    const seq = this.entries.length;
    const prevHash = seq === 0 ? '' : this.entries[seq - 1]!.hash;
    const entry = seal(draft, seq, prevHash);
    this.entries.push(entry);
    if (this.filePath) await appendFile(this.filePath, JSON.stringify(entry) + '\n', 'utf8');
    return entry;
  }

  async list(runId?: string): Promise<AuditEntry[]> {
    await this.ensureLoaded();
    return runId ? this.entries.filter((e) => e.runId === runId) : [...this.entries];
  }

  async verify(): Promise<{ ok: boolean; brokenAt?: number }> {
    await this.ensureLoaded();
    let prevHash = '';
    for (const entry of this.entries) {
      const { hash, ...rest } = entry;
      if (entry.prevHash !== prevHash || hashEntry(rest) !== hash) {
        return { ok: false, brokenAt: entry.seq };
      }
      prevHash = hash;
    }
    return { ok: true };
  }
}
