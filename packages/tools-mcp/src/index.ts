import type { Finding } from '@k8s-sentinel/core';
import { TrivyScanner } from './trivy.js';
import { KubescapeScanner } from './kubescape.js';
import { KubeBenchScanner } from './kube-bench.js';
import { FalcoScanner } from './falco.js';
import type { Scanner, ScanResult, ScanTarget } from './types.js';

export * from './types.js';
export { TrivyScanner } from './trivy.js';
export { KubescapeScanner } from './kubescape.js';
export { KubeBenchScanner } from './kube-bench.js';
export { FalcoScanner } from './falco.js';
export { normalizeSeverity } from './severity.js';

/** All scanners the Collector orchestrates. */
export function allScanners(): Scanner[] {
  return [new TrivyScanner(), new KubescapeScanner(), new KubeBenchScanner(), new FalcoScanner()];
}

export interface MultiScanResult {
  findings: Finding[];
  results: ScanResult[];
}

/**
 * Run every scanner in parallel and merge their normalized findings.
 * A single scanner failing never aborts the others (Feature 1, BUILD.md §1).
 */
export async function runAllScanners(
  target: ScanTarget = {},
  scanners: Scanner[] = allScanners(),
): Promise<MultiScanResult> {
  const results = await Promise.all(
    scanners.map(async (s): Promise<ScanResult> => {
      try {
        return await s.run(target);
      } catch (err) {
        return {
          source: s.source,
          findings: [],
          usedFixture: false,
          durationMs: 0,
          warning: `scanner crashed: ${(err as Error).message}`,
        };
      }
    }),
  );
  return { results, findings: results.flatMap((r) => r.findings) };
}
