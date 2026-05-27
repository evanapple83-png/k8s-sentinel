import { z } from 'zod';
import { ResourceRefSchema } from './findings.js';

/**
 * A correlated attack path — the core product. Several siloed findings combine
 * into a single ranked narrative:
 *   vuln in image → container actually running → service internet-exposed →
 *   pod over-privileged (hostPath / privileged) → can reach a cluster secret.
 *
 * The `score` is reachability-weighted, not a sum of CVSS values.
 */

export const AttackStepSchema = z.object({
  /** One link in the chain, e.g. "exposed", "running", "over-privileged". */
  kind: z.enum([
    'exposed', // reachable from outside the cluster / namespace
    'running', // workload is actually scheduled and running
    'vulnerable', // has an exploitable vuln
    'over-privileged', // excessive RBAC / securityContext
    'lateral-move', // can pivot to another resource
    'secret-access', // can read a secret / credential
    'data-exfil', // terminal: data can leave
  ]),
  resource: ResourceRefSchema,
  detail: z.string(),
  findingIds: z.array(z.string()).default([]),
});
export type AttackStep = z.infer<typeof AttackStepSchema>;

export const AttackPathSchema = z.object({
  id: z.string(),
  /** Human-readable chain, written by the Analyst. */
  narrative: z.string(),
  steps: z.array(AttackStepSchema).min(1),
  /** 0–100, ranks paths against each other. */
  score: z.number().min(0).max(100),
  /** All findings that participate in this path. */
  findingIds: z.array(z.string()),
  /** "internet" | "namespace" | "node" | "in-cluster" — where it starts. */
  entryPoint: z.string().optional(),
  createdAt: z.string().datetime().optional(),
});
export type AttackPath = z.infer<typeof AttackPathSchema>;

export function parseAttackPaths(input: unknown): AttackPath[] {
  return z.array(AttackPathSchema).parse(input);
}
