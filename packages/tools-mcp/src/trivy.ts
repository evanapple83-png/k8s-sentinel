import { type Finding, makeFindingId, sanitizeObject } from '@k8s-sentinel/core';
import { BaseScanner, parseJson } from './base-scanner.js';
import { normalizeSeverity } from './severity.js';
import type { ScanTarget } from './types.js';

/** Trivy: image & IaC/misconfig scanning. Parses `trivy ... -f json` output. */
export class TrivyScanner extends BaseScanner {
  readonly source = 'trivy' as const;
  readonly binary = 'trivy';
  protected readonly fixtureName = 'trivy.json';

  protected buildArgs(target: ScanTarget): string[] {
    if (target.images?.length) {
      return ['image', '--quiet', '--format', 'json', target.images[0]!];
    }
    const args = ['k8s', '--quiet', '--format', 'json', '--report', 'all'];
    if (target.namespace) args.push('--namespace', target.namespace);
    if (target.kubeconfig) args.push('--kubeconfig', target.kubeconfig);
    return args;
  }

  protected parseOutput = parseJson;

  normalize(raw: unknown): Finding[] {
    const root = raw as TrivyReport;
    const results = root?.Results ?? collectK8sResults(root);
    const findings: Finding[] = [];

    for (const result of results ?? []) {
      const image = result.Target ?? result.Class ?? undefined;
      const resource = {
        kind: 'Image',
        name: result.Target ?? 'unknown',
        ...(image ? { image } : {}),
      };

      for (const v of result.Vulnerabilities ?? []) {
        const ruleId = v.VulnerabilityID ?? 'CVE-UNKNOWN';
        findings.push({
          id: makeFindingId('trivy', ruleId, resource),
          source: 'trivy',
          ruleId,
          title: v.Title ?? `${v.PkgName ?? 'package'} ${ruleId}`,
          description: v.Description ?? '',
          severity: normalizeSeverity(v.Severity),
          resource,
          baseScore: cvssScore(v),
          raw: sanitizeObject(v),
        });
      }

      for (const m of result.Misconfigurations ?? []) {
        const ruleId = m.ID ?? 'MISCONF';
        findings.push({
          id: makeFindingId('trivy', ruleId, resource),
          source: 'trivy',
          ruleId,
          title: m.Title ?? ruleId,
          description: m.Description ?? m.Message ?? '',
          severity: normalizeSeverity(m.Severity),
          resource,
          raw: sanitizeObject(m),
        });
      }
    }
    return findings;
  }
}

function collectK8sResults(root: TrivyReport): TrivyResult[] {
  // `trivy k8s` nests per-resource Results under a Resources[] array.
  const out: TrivyResult[] = [];
  for (const r of root?.Resources ?? []) out.push(...(r.Results ?? []));
  return out;
}

function cvssScore(v: TrivyVuln): number | undefined {
  const nvd = v.CVSS?.nvd?.V3Score ?? v.CVSS?.redhat?.V3Score;
  return typeof nvd === 'number' ? nvd : undefined;
}

interface TrivyReport {
  Results?: TrivyResult[];
  Resources?: { Results?: TrivyResult[] }[];
}
interface TrivyResult {
  Target?: string;
  Class?: string;
  Vulnerabilities?: TrivyVuln[];
  Misconfigurations?: TrivyMisconf[];
}
interface TrivyVuln {
  VulnerabilityID?: string;
  PkgName?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  CVSS?: { nvd?: { V3Score?: number }; redhat?: { V3Score?: number } };
}
interface TrivyMisconf {
  ID?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Severity?: string;
}
