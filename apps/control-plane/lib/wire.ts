import 'server-only';
import { z } from 'zod';

/**
 * Ingest validation (Phase 5, hybrid mode). The relay forwards each posture push
 * here over an authenticated webhook. Even though the agent already validated it
 * against the wire contract in-cluster, this is a TRUST BOUNDARY on the hosted
 * side, so we re-validate + size-cap before anything touches the database.
 *
 * This is a deliberate LOCAL MIRROR of @k8s-sentinel/relay-protocol's
 * PostureSnapshot — the control-plane stays a standalone app with no workspace
 * deps (see DEPLOY.md), exactly like lib/types.ts mirrors the orchestrator shapes.
 */

const Str = (max = 4096) => z.string().max(max);
const ShortStr = (max = 256) => z.string().max(max);

const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
const SsvcDecision = z.enum(['Act', 'Attend', 'Track', 'Track*']);
const Confidence = z.enum(['high', 'medium', 'n/a']);
const Exposure = z.enum(['open', 'internal', 'small', 'cluster']);

const ResourceRef = z.object({
  kind: ShortStr(),
  name: ShortStr(),
  namespace: ShortStr().optional(),
  image: ShortStr(512).optional(),
  path: ShortStr(1024).optional(),
});

const ControlRef = z.object({ framework: ShortStr(), id: ShortStr(), title: ShortStr().optional() });

const WireFinding = z.object({
  id: ShortStr(),
  source: ShortStr(),
  ruleId: ShortStr(),
  title: Str(),
  description: Str(16384).optional(),
  severity: Severity,
  resource: ResourceRef,
  reachable: z.boolean().optional(),
  exploitScore: z.number().finite().optional(),
  attackPathId: ShortStr().optional(),
  controls: z.array(ControlRef).max(64).optional(),
  baseScore: z.number().finite().optional(),
  // v3 attack-graph fields (all optional; legacy agents omit)
  cve: ShortStr(64).optional(),
  kev: z.boolean().optional(),
  ransomware: z.boolean().optional(),
  epss: z.number().min(0).max(1).optional(),
  ssvc: SsvcDecision.optional(),
  confidence: Confidence.optional(),
  exposure: Exposure.optional(),
  reaches: z.array(ShortStr(64)).max(32).optional(),
});

const ChokeControl = z.object({
  type: ShortStr(64),
  ref: ShortStr(128).optional(),
  workload: ShortStr(256).optional(),
  sa: ShortStr(256).optional(),
  what: ShortStr(128).optional(),
  role: ShortStr(256).optional(),
});

const WireChokePoint = z.object({
  id: ShortStr(),
  control: ChokeControl,
  breaks: z.number().int().nonnegative(),
  totalPaths: z.number().int().nonnegative(),
  targets: z.array(ShortStr(256)).max(64),
  severity: Severity,
  description: Str(4096),
  priority: z.number().finite(),
});

const WireThreatIntel = z.object({
  source: ShortStr(64),
  version: ShortStr(64),
  kevCount: z.number().int().nonnegative(),
  epssCount: z.number().int().nonnegative().optional(),
});

const WireAttackPath = z.object({
  id: ShortStr(),
  narrative: Str(16384),
  score: z.number().finite(),
  entryPoint: ShortStr().optional(),
  steps: z
    .array(
      z.object({
        kind: ShortStr(),
        resource: ResourceRef,
        detail: Str(),
        findingIds: z.array(ShortStr()).max(512),
      }),
    )
    .max(128),
  findingIds: z.array(ShortStr()).max(2048),
});

const WireRemediation = z.object({
  id: ShortStr(),
  playbookId: ShortStr(),
  title: Str(),
  severity: Severity,
  kind: z.enum(['patch', 'new-file', 'manual']),
  rationale: Str(16384),
  path: ShortStr(1024),
  diff: Str(131072),
  manualSteps: z.array(Str()).max(64),
  controls: z.array(ControlRef).max(64),
  findingIds: z.array(ShortStr()).max(2048),
  attackPathId: ShortStr().optional(),
  priority: z.number().finite(),
  branch: ShortStr(),
  prTitle: Str(),
  prBody: Str(131072),
});

const WireAuditEntry = z.object({
  seq: z.number().int().nonnegative(),
  ts: ShortStr(64),
  actor: ShortStr(64),
  agent: ShortStr(64).optional(),
  action: ShortStr(128),
  runId: ShortStr().optional(),
});

const WireRun = z.object({
  id: ShortStr(),
  status: z.enum(['running', 'complete', 'failed']),
  engine: ShortStr(),
  usedFixtures: z.boolean(),
  findingCount: z.number().int().nonnegative(),
  pathCount: z.number().int().nonnegative(),
  riskScore: z.number().finite().nullable(),
  summary: Str(16384).nullable(),
  startedAt: ShortStr(64),
  finishedAt: ShortStr(64).nullable().optional(),
});

export const PostureSnapshotSchema = z.object({
  run: WireRun,
  findings: z.array(WireFinding).max(20000),
  paths: z.array(WireAttackPath).max(2000),
  remediations: z.array(WireRemediation).max(2000),
  audit: z.array(WireAuditEntry).max(20000),
  // v3 (optional; agents pre-ARGUS omit). Mirrors relay-protocol.
  intel: WireThreatIntel.optional(),
  chokePoints: z.array(WireChokePoint).max(256).optional(),
});

export type PostureSnapshot = z.infer<typeof PostureSnapshotSchema>;

export const IngestBodySchema = z.object({
  clusterId: z.string().uuid(),
  snapshot: PostureSnapshotSchema,
});

export type IngestBody = z.infer<typeof IngestBodySchema>;
