import { readFileSync } from 'node:fs';
import { hardenFindings, type Finding, type ScannerSource } from '@k8s-sentinel/core';
import { isOnPath, run } from './exec.js';
import type { Scanner, ScanResult, ScanTarget } from './types.js';

const DEFAULT_TIMEOUT = 120_000;

/**
 * Shared scan lifecycle: try the real CLI; on absence or parse failure, fall
 * back to a bundled fixture so the whole pipeline runs offline (CLAUDE.md).
 * Subclasses provide arg construction, output parsing, and normalization.
 */
export abstract class BaseScanner implements Scanner {
  abstract readonly source: ScannerSource;
  abstract readonly binary: string;
  /** Fixture file name under packages/tools-mcp/fixtures/. */
  protected abstract readonly fixtureName: string;

  protected abstract buildArgs(target: ScanTarget): string[];
  /** Parse raw stdout into the scanner's native JSON shape. */
  protected abstract parseOutput(stdout: string): unknown;
  abstract normalize(raw: unknown): Finding[];

  async isAvailable(): Promise<boolean> {
    return isOnPath(this.binary);
  }

  async run(target: ScanTarget): Promise<ScanResult> {
    const start = Date.now();
    const timeoutMs = target.timeoutMs ?? DEFAULT_TIMEOUT;

    if (await this.isAvailable()) {
      const { stdout, stderr } = await run(this.binary, this.buildArgs(target), { timeoutMs });
      try {
        const raw = this.parseOutput(stdout);
        return {
          source: this.source,
          findings: this.normalizeHardened(raw),
          usedFixture: false,
          durationMs: Date.now() - start,
          ...(stderr.trim() ? { warning: truncate(stderr) } : {}),
        };
      } catch (err) {
        return {
          ...this.fixtureResult(start),
          warning: `parse failed (${(err as Error).message}); used fixture`,
        };
      }
    }

    return {
      ...this.fixtureResult(start),
      warning: `${this.binary} not on PATH; used bundled fixture`,
    };
  }

  protected loadFixture(): unknown {
    const url = new URL(`../fixtures/${this.fixtureName}`, import.meta.url);
    return JSON.parse(readFileSync(url, 'utf8'));
  }

  /**
   * Single enforced chokepoint (BUILD.md §10): every path that produces
   * findings — live CLI or bundled fixture — goes through here, so the
   * normalized display fields are always defanged before leaving the scanner.
   */
  private normalizeHardened(raw: unknown): Finding[] {
    return hardenFindings(this.normalize(raw));
  }

  private fixtureResult(start: number): ScanResult {
    return {
      source: this.source,
      findings: this.normalizeHardened(this.loadFixture()),
      usedFixture: true,
      durationMs: Date.now() - start,
    };
  }
}

function truncate(s: string, n = 300): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/** Default JSON parse used by most scanners. */
export function parseJson(stdout: string): unknown {
  return JSON.parse(stdout);
}

/** JSON Lines parse (Falco emits one event per line). */
export function parseJsonLines(stdout: string): unknown[] {
  return stdout
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}
