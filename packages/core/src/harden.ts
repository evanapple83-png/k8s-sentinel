import type { Finding } from './findings.js';
import { sanitizeUntrusted } from './sanitize.js';

/**
 * Scan-input hardening (BUILD.md §10, Phase 4).
 *
 * `sanitizeObject` already scrubs each finding's raw tool payload, but the
 * NORMALIZED display fields (`title`, `description`, `resource.*`) are also
 * attacker-controlled — an image tag, CVE title or annotation can carry a
 * prompt-injection payload, and those fields are exactly what reaches agent
 * prompts and reports. This is the single enforced chokepoint that defangs
 * every untrusted string of a normalized finding right after collection, so no
 * downstream consumer can forget to. Strip-only (no data fence): the analyst
 * and author still fence/clamp on render. Stable id and ruleId are left intact
 * so finding identity stays consistent across scans.
 */

const TITLE_MAX = 300;
const NAME_MAX = 253; // RFC-1123 max name length
const DESC_MAX = 4000;

function clean(value: string | undefined, maxLength: number): string | undefined {
  if (value === undefined) return undefined;
  return sanitizeUntrusted(value, { fence: false, maxLength });
}

/** Defang the untrusted string fields of one normalized finding. */
export function hardenFinding(finding: Finding): Finding {
  const r = finding.resource;
  return {
    ...finding,
    title: clean(finding.title, TITLE_MAX) ?? finding.title,
    description: clean(finding.description, DESC_MAX) ?? '',
    resource: {
      ...r,
      name: clean(r.name, NAME_MAX) ?? r.name,
      ...(r.image !== undefined ? { image: clean(r.image, NAME_MAX)! } : {}),
      ...(r.path !== undefined ? { path: clean(r.path, NAME_MAX)! } : {}),
      ...(r.namespace !== undefined ? { namespace: clean(r.namespace, NAME_MAX)! } : {}),
    },
  };
}

/** Harden a batch of findings (the Collector applies this to every scanner). */
export function hardenFindings(findings: Finding[]): Finding[] {
  return findings.map(hardenFinding);
}
