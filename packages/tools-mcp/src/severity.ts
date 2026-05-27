import type { Severity } from '@k8s-sentinel/core';

/** Map any scanner's severity/priority vocabulary onto our common scale. */
export function normalizeSeverity(input: string | undefined | null): Severity {
  const s = (input ?? '').toString().trim().toLowerCase();
  switch (s) {
    case 'critical':
    case 'crit':
    case 'emergency':
      return 'critical';
    case 'high':
    case 'error':
    case 'fail': // kube-bench failed check
      return 'high';
    case 'medium':
    case 'moderate':
    case 'warning':
    case 'warn':
      return 'medium';
    case 'low':
    case 'notice':
      return 'low';
    case 'unknown':
    case 'informational':
    case 'info':
    case 'debug':
    case 'negligible':
    case 'none':
    case 'pass':
      return 'info';
    default:
      return 'medium'; // fail safe: unknown → mid, never silently drop
  }
}
