import type { ControlRef, Finding } from '@k8s-sentinel/core';

/**
 * Compliance mapping (BUILD.md §3, Feature 2). Every finding is mapped to the
 * controls it violates across CIS Kubernetes Benchmark, NSA-CISA Kubernetes
 * Hardening Guidance, SOC 2 Trust Services Criteria, and MITRE ATT&CK.
 *
 * The map is intentionally static and auditable — a regulated buyer must be
 * able to see exactly why a finding maps to a control. Unknown rules fall back
 * to a source-level mapping so nothing is left uncategorized.
 */

/** Explicit per-rule mappings, keyed by the scanner-native rule id. */
const RULE_CONTROLS: Record<string, ControlRef[]> = {
  // ── Kubescape controls ────────────────────────────────────────────────
  'C-0057': [
    { framework: 'CIS', id: 'CIS-5.2.5', title: 'Minimize privileged containers' },
    { framework: 'NSA-CISA', id: 'NSA-PodSecurity', title: 'Non-privileged containers' },
    { framework: 'SOC2', id: 'SOC2-CC6.1', title: 'Logical access controls' },
    { framework: 'MITRE-ATTACK', id: 'T1610', title: 'Deploy Container' },
  ],
  'C-0017': [
    { framework: 'CIS', id: 'CIS-5.2.12', title: 'Immutable container filesystem' },
    { framework: 'NSA-CISA', id: 'NSA-ImmutableFS', title: 'Read-only root filesystem' },
  ],
  'C-0186': [
    { framework: 'CIS', id: 'CIS-5.2.6', title: 'Minimize allowPrivilegeEscalation' },
    { framework: 'NSA-CISA', id: 'NSA-PrivEsc', title: 'Prevent privilege escalation' },
    { framework: 'MITRE-ATTACK', id: 'T1611', title: 'Escape to Host' },
  ],
  'C-0256': [
    { framework: 'NSA-CISA', id: 'NSA-NetworkExposure', title: 'Limit network exposure' },
    { framework: 'SOC2', id: 'SOC2-CC6.6', title: 'Boundary protection' },
    { framework: 'MITRE-ATTACK', id: 'T1133', title: 'External Remote Services' },
  ],
  'C-0260': [
    { framework: 'CIS', id: 'CIS-5.3.2', title: 'Apply NetworkPolicy to all namespaces' },
    { framework: 'NSA-CISA', id: 'NSA-NetworkSeparation', title: 'Network separation & hardening' },
  ],
};

/** Source-level fallback when a specific rule isn't in the table. */
const SOURCE_CONTROLS: Record<Finding['source'], ControlRef[]> = {
  trivy: [
    { framework: 'SOC2', id: 'SOC2-CC7.1', title: 'Vulnerability management' },
    { framework: 'MITRE-ATTACK', id: 'T1190', title: 'Exploit Public-Facing Application' },
  ],
  kubescape: [{ framework: 'NSA-CISA', id: 'NSA-PodSecurity', title: 'Kubernetes Pod hardening' }],
  'kube-bench': [{ framework: 'SOC2', id: 'SOC2-CC6.8', title: 'Configuration management' }],
  falco: [
    { framework: 'SOC2', id: 'SOC2-CC7.2', title: 'Anomaly & threat detection' },
    { framework: 'MITRE-ATTACK', id: 'TA0002', title: 'Execution (runtime)' },
  ],
};

/**
 * kube-bench rule ids ARE CIS Kubernetes Benchmark section numbers (e.g.
 * "1.2.1"), so we map them straight through to a CIS control id.
 */
function kubeBenchControl(ruleId: string): ControlRef | undefined {
  if (/^\d+(\.\d+)+$/.test(ruleId)) {
    return { framework: 'CIS', id: `CIS-${ruleId}`, title: 'CIS Kubernetes Benchmark' };
  }
  return undefined;
}

/** All controls a single finding maps to (deduped by framework+id). */
export function mapControls(finding: Finding): ControlRef[] {
  const out: ControlRef[] = [];
  const seen = new Set<string>();
  const push = (c: ControlRef) => {
    const key = `${c.framework}:${c.id}`;
    if (!seen.has(key)) {
      seen.add(key);
      out.push(c);
    }
  };

  for (const c of RULE_CONTROLS[finding.ruleId] ?? []) push(c);

  if (finding.source === 'kube-bench') {
    const cis = kubeBenchControl(finding.ruleId);
    if (cis) push(cis);
  }

  // Fall back to source-level controls when nothing rule-specific applied.
  if (out.length === 0) {
    for (const c of SOURCE_CONTROLS[finding.source]) push(c);
  }

  return out;
}

/** Annotate findings in place-style (returns new objects) with `controls`. */
export function withControls(findings: Finding[]): Finding[] {
  return findings.map((f) => ({ ...f, controls: mapControls(f) }));
}

/** Roll up coverage: how many findings touch each framework (for the report). */
export function complianceSummary(findings: Finding[]): Record<ControlRef['framework'], number> {
  const tally: Record<string, number> = {};
  for (const f of findings) {
    const frameworks = new Set((f.controls ?? mapControls(f)).map((c) => c.framework));
    for (const fw of frameworks) tally[fw] = (tally[fw] ?? 0) + 1;
  }
  return tally as Record<ControlRef['framework'], number>;
}
