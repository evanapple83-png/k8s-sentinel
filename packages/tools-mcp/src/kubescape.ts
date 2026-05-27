import { type Finding, makeFindingId, sanitizeObject, type Severity } from '@k8s-sentinel/core';
import { BaseScanner, parseJson } from './base-scanner.js';
import type { ScanTarget } from './types.js';

/**
 * Kubescape: posture / misconfiguration scanning against frameworks
 * (NSA, MITRE, CIS). Parses the v2 JSON resource-association format.
 */
export class KubescapeScanner extends BaseScanner {
  readonly source = 'kubescape' as const;
  readonly binary = 'kubescape';
  protected readonly fixtureName = 'kubescape.json';

  protected buildArgs(target: ScanTarget): string[] {
    const args = ['scan', '--format', 'json', '--format-version', 'v2'];
    if (target.namespace) args.push('--include-namespaces', target.namespace);
    if (target.kubeconfig) args.push('--kubeconfig', target.kubeconfig);
    return args;
  }

  protected parseOutput = parseJson;

  normalize(raw: unknown): Finding[] {
    const root = raw as KubescapeReport;
    const resourceById = new Map<string, KubescapeResource['object']>();
    for (const r of root?.resources ?? []) {
      if (r.resourceID) resourceById.set(r.resourceID, r.object);
    }

    const findings: Finding[] = [];
    for (const result of root?.results ?? []) {
      const obj = result.resourceID ? resourceById.get(result.resourceID) : undefined;
      const resource = {
        kind: obj?.kind ?? 'Unknown',
        name: obj?.metadata?.name ?? result.resourceID ?? 'unknown',
        ...(obj?.metadata?.namespace ? { namespace: obj.metadata.namespace } : {}),
      };

      for (const control of result.controls ?? []) {
        if (control.status?.status !== 'failed') continue;
        const ruleId = control.controlID ?? 'C-UNKNOWN';
        findings.push({
          id: makeFindingId('kubescape', ruleId, resource),
          source: 'kubescape',
          ruleId,
          title: control.name ?? ruleId,
          description: control.name ?? '',
          severity: severityFromScore(control.scoreFactor),
          resource,
          baseScore: control.scoreFactor,
          raw: sanitizeObject(control),
        });
      }
    }
    return findings;
  }
}

function severityFromScore(score: number | undefined): Severity {
  if (score === undefined) return 'medium';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

interface KubescapeReport {
  results?: KubescapeResult[];
  resources?: KubescapeResource[];
}
interface KubescapeResult {
  resourceID?: string;
  controls?: KubescapeControl[];
}
interface KubescapeControl {
  controlID?: string;
  name?: string;
  scoreFactor?: number;
  status?: { status?: string };
}
interface KubescapeResource {
  resourceID?: string;
  object?: { kind?: string; metadata?: { name?: string; namespace?: string } };
}
