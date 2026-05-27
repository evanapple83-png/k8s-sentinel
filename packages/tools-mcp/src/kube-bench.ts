import { type Finding, makeFindingId, sanitizeObject } from '@k8s-sentinel/core';
import { BaseScanner, parseJson } from './base-scanner.js';
import { normalizeSeverity } from './severity.js';
import type { ScanTarget } from './types.js';

/**
 * kube-bench: CIS Kubernetes Benchmark checks on the control plane / nodes.
 * Parses `kube-bench --json` output. Only FAIL / WARN become findings.
 */
export class KubeBenchScanner extends BaseScanner {
  readonly source = 'kube-bench' as const;
  readonly binary = 'kube-bench';
  protected readonly fixtureName = 'kube-bench.json';

  protected buildArgs(_target: ScanTarget): string[] {
    return ['--json', '--noremediations=false'];
  }

  protected parseOutput = parseJson;

  normalize(raw: unknown): Finding[] {
    const root = raw as KubeBenchReport;
    const findings: Finding[] = [];

    for (const control of root?.Controls ?? []) {
      const nodeType = control.node_type ?? 'node';
      const resource = { kind: 'Node', name: nodeType };

      for (const test of control.tests ?? []) {
        for (const r of test.results ?? []) {
          const status = (r.status ?? '').toUpperCase();
          if (status !== 'FAIL' && status !== 'WARN') continue;
          const ruleId = r.test_number ?? 'CIS-UNKNOWN';
          findings.push({
            id: makeFindingId('kube-bench', ruleId, { ...resource, path: ruleId }),
            source: 'kube-bench',
            ruleId,
            title: r.test_desc ?? ruleId,
            description: r.remediation ?? '',
            // FAIL → high, WARN → medium (see severity map).
            severity: normalizeSeverity(status),
            resource,
            raw: sanitizeObject(r),
          });
        }
      }
    }
    return findings;
  }
}

interface KubeBenchReport {
  Controls?: KubeBenchControl[];
}
interface KubeBenchControl {
  node_type?: string;
  tests?: { results?: KubeBenchResult[] }[];
}
interface KubeBenchResult {
  test_number?: string;
  test_desc?: string;
  status?: string;
  remediation?: string;
}
