/**
 * Domain types for the hosted control-plane.
 *
 * The lower half (Finding/AttackPath/Run/…) mirrors the orchestrator wire types
 * — the SAME normalized shapes the in-cluster agent streams upstream through the
 * relay. The upper half (Account/Membership/Cluster/InstallToken) is the
 * multi-tenant model that only exists in the hosted plane (BUILD.md: hybrid
 * mode). Raw cluster data never lives here — see docs/DATA-BOUNDARY.md.
 */

// --- Multi-tenant model -----------------------------------------------------

export type Role = 'viewer' | 'approver' | 'admin';

export interface Account {
  id: string;
  name: string;
  createdAt: string;
}

export interface Membership {
  accountId: string;
  userId: string;
  role: Role;
  mfaEnrolled: boolean;
}

export type ClusterStatus = 'pending' | 'connected' | 'disconnected';

export interface Cluster {
  id: string;
  accountId: string;
  name: string;
  status: ClusterStatus;
  agentVersion: string | null;
  mode: 'hybrid' | 'cluster-local';
  lastSeenAt: string | null;
  connectedAt: string | null;
  createdAt: string;
}

export interface InstallToken {
  id: string;
  accountId: string;
  /** Shown once at mint time; stored only as a hash. */
  token?: string;
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
}

// --- Orchestrator wire shapes (streamed up from the agent) ------------------

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// --- ARGUS v3 attack-graph attributes (per-finding + per-run + choke-points)
export type SsvcDecision = 'Act' | 'Attend' | 'Track' | 'Track*';
export type Confidence = 'high' | 'medium' | 'n/a';
export type Exposure = 'open' | 'internal' | 'small' | 'cluster';

export interface ThreatIntel {
  source: string;
  version: string;
  kevCount: number;
  epssCount?: number;
}

export interface ChokeControl {
  type: string;
  ref?: string;
  workload?: string;
  sa?: string;
  what?: string;
  role?: string;
}

export interface ChokePoint {
  id: string;
  control: ChokeControl;
  breaks: number;
  totalPaths: number;
  targets: string[];
  severity: Severity;
  description: string;
  priority: number;
}

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
  // ARGUS v3 attack-graph fields (all optional; legacy runs omit)
  cve?: string;
  kev?: boolean;
  ransomware?: boolean;
  epss?: number;
  ssvc?: SsvcDecision;
  confidence?: Confidence;
  exposure?: Exposure;
  reaches?: string[];
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
  clusterId: string;
  createdAt: string;
  status: 'running' | 'complete' | 'failed';
  engine: string;
  usedFixtures: boolean;
  findingCount: number;
  pathCount: number;
  riskScore: number | null;
  summary: string | null;
  /** ARGUS v3 threat-intel catalog pinned at scan time (optional). */
  intel?: ThreatIntel | null;
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

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  agent?: string;
  action: string;
  runId?: string;
}

export interface RunSnapshot {
  run: RunRecord;
  findings: Finding[];
  paths: AttackPath[];
  fixes: Fix[];
  /** ARGUS v3 choke-points (priority desc). Omitted for legacy runs. */
  chokePoints?: ChokePoint[];
}
