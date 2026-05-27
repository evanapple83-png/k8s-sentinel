import { existsSync, readFileSync } from 'node:fs';
import { type Finding, makeFindingId, sanitizeObject } from '@k8s-sentinel/core';
import { BaseScanner, parseJsonLines } from './base-scanner.js';
import { normalizeSeverity } from './severity.js';
import type { ScanResult, ScanTarget } from './types.js';

/**
 * Falco: runtime threat detection. Unlike the others it is a passive sensor,
 * so the Collector consumes its emitted event stream (JSONL) rather than
 * launching a scan. Set FALCO_EVENTS_FILE to the alerts file; otherwise the
 * bundled fixture is used.
 */
export class FalcoScanner extends BaseScanner {
  readonly source = 'falco' as const;
  readonly binary = 'falco';
  protected readonly fixtureName = 'falco.jsonl';

  protected buildArgs(): string[] {
    return [];
  }

  protected parseOutput(stdout: string): unknown {
    return parseJsonLines(stdout);
  }

  override async isAvailable(): Promise<boolean> {
    const file = process.env.FALCO_EVENTS_FILE;
    return Boolean(file && existsSync(file));
  }

  override async run(_target: ScanTarget): Promise<ScanResult> {
    const start = Date.now();
    const file = process.env.FALCO_EVENTS_FILE;
    if (file && existsSync(file)) {
      try {
        const events = parseJsonLines(readFileSync(file, 'utf8'));
        return {
          source: this.source,
          findings: this.normalize(events),
          usedFixture: false,
          durationMs: Date.now() - start,
        };
      } catch (err) {
        return {
          source: this.source,
          findings: this.normalize(this.loadFixtureLines()),
          usedFixture: true,
          durationMs: Date.now() - start,
          warning: `falco events parse failed (${(err as Error).message}); used fixture`,
        };
      }
    }
    return {
      source: this.source,
      findings: this.normalize(this.loadFixtureLines()),
      usedFixture: true,
      durationMs: Date.now() - start,
      warning: 'FALCO_EVENTS_FILE unset; used bundled fixture',
    };
  }

  private loadFixtureLines(): unknown[] {
    const url = new URL(`../fixtures/${this.fixtureName}`, import.meta.url);
    return parseJsonLines(readFileSync(url, 'utf8'));
  }

  normalize(raw: unknown): Finding[] {
    const events = Array.isArray(raw) ? (raw as FalcoEvent[]) : [];
    return events.map((ev) => {
      const f = ev.output_fields ?? {};
      const podName = f['k8s.pod.name'] ?? f['container.name'] ?? 'unknown';
      const ns = f['k8s.ns.name'];
      const resource = {
        kind: 'Pod',
        name: podName,
        ...(ns ? { namespace: ns } : {}),
      };
      const ruleId = ev.rule ?? 'falco-rule';
      return {
        id: makeFindingId('falco', ruleId, { ...resource, path: ev.time }),
        source: 'falco' as const,
        ruleId,
        title: ev.rule ?? 'Runtime alert',
        description: ev.output ?? '',
        severity: normalizeSeverity(ev.priority),
        resource,
        observedAt: normalizeTime(ev.time),
        raw: sanitizeObject(ev),
      };
    });
  }
}

function normalizeTime(t: string | undefined): string | undefined {
  if (!t) return undefined;
  const d = new Date(t);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

interface FalcoEvent {
  time?: string;
  priority?: string;
  rule?: string;
  output?: string;
  output_fields?: Record<string, string>;
}
