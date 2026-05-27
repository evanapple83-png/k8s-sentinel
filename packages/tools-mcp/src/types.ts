import type { Finding, ScannerSource } from '@k8s-sentinel/core';

/** What to scan. All fields optional → scanners use sensible cluster-wide defaults. */
export interface ScanTarget {
  /** Read-only kubeconfig path (execution plane mounts this). */
  kubeconfig?: string;
  /** Restrict to a namespace where the scanner supports it. */
  namespace?: string;
  /** Specific images to scan (Trivy image mode). */
  images?: string[];
  /** Per-scanner timeout in ms. */
  timeoutMs?: number;
}

export interface ScanResult {
  source: ScannerSource;
  findings: Finding[];
  /** True when the scanner binary was absent and a fixture was used instead. */
  usedFixture: boolean;
  /** Wall-clock duration of the scan. */
  durationMs: number;
  /** Non-fatal warning (e.g. CLI missing, partial parse). */
  warning?: string;
}

export interface Scanner {
  readonly source: ScannerSource;
  /** Name of the CLI binary this scanner shells out to. */
  readonly binary: string;
  /** Is the binary on PATH? */
  isAvailable(): Promise<boolean>;
  /** Run the scan; falls back to a bundled fixture when the binary is absent. */
  run(target: ScanTarget): Promise<ScanResult>;
  /** Pure: turn raw scanner JSON into normalized findings. Exported for tests. */
  normalize(raw: unknown): Finding[];
}
