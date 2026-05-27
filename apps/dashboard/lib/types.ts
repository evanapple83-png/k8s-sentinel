/**
 * Wire types — the JSON shapes the orchestrator API returns. Kept local so the
 * dashboard stays a standalone browser app and never imports the Node-only
 * backend packages.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ResourceRef {
  kind: string;
  name: string;
  namespace?: string;
  image?: string;
  path?: string;
}

export interface ControlRef {
  framework: string;
  id: string;
  title?: string;
}

export interface Finding {
  id: string;
  source: string;
  ruleId: string;
  title: string;
  description?: string;
  severity: Severity;
  resource: ResourceRef;
  reachable?: boolean;
  exploitScore?: number;
  attackPathId?: string;
  controls?: ControlRef[];
  baseScore?: number;
}

export interface AttackStep {
  kind: string;
  resource: ResourceRef;
  detail: string;
  findingIds: string[];
}

export interface AttackPath {
  id: string;
  narrative: string;
  score: number;
  entryPoint?: string;
  steps: AttackStep[];
  findingIds: string[];
}

export interface RunRecord {
  id: string;
  createdAt: string;
  status: 'running' | 'complete' | 'failed';
  engine: string;
  usedFixtures: boolean;
  findingCount: number;
  pathCount: number;
  riskScore: number | null;
  summary: string | null;
}

export interface Fix {
  id: string;
  playbookId: string;
  title: string;
  severity: Severity;
  kind: 'patch' | 'new-file' | 'manual';
  rationale: string;
  path: string;
  diff: string;
  manualSteps: string[];
  controls: ControlRef[];
  findingIds: string[];
  attackPathId?: string;
  priority: number;
  status: string;
  branch: string;
  prTitle: string;
  prBody: string;
  approved?: boolean;
}

export interface RunSnapshot {
  run: RunRecord;
  findings: Finding[];
  paths: AttackPath[];
  fixes: Fix[];
}

export interface AskResult {
  runId: string;
  answer: { answer: string; findings: Finding[]; parsed?: { unmatched?: string } };
}

export interface ApproveResult {
  approved: string;
  branch: string;
  bundleDir: string;
  files: number;
  note: string;
}

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  agent?: string;
  action: string;
  runId?: string;
}

export interface ScanDoneEvent {
  runId: string;
  riskScore: number | null;
  summary: string | null;
  usedFixtures: boolean;
  findingCount: number;
  pathCount: number;
  proposalCount: number;
}
