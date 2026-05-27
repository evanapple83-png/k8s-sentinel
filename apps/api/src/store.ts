import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { AttackPath, ClusterInventory, Finding } from '@k8s-sentinel/core';

export type RunStatus = 'running' | 'complete' | 'failed';

export interface RunRecord {
  id: string;
  createdAt: string;
  status: RunStatus;
  engine: string;
  usedFixtures: boolean;
  findingCount: number;
  pathCount: number;
  riskScore: number | null;
  summary: string | null;
}

/**
 * SQLite datastore (MVP; swappable for Postgres later). Persists runs,
 * normalized findings, the cluster inventory snapshot, and correlated attack
 * paths. Uses Node's built-in `node:sqlite` — no native build step.
 */
export class SqliteStore {
  private readonly db: DatabaseSync;

  constructor(dbPath: string) {
    if (dbPath !== ':memory:') mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS runs (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        status TEXT NOT NULL,
        engine TEXT NOT NULL,
        used_fixtures INTEGER NOT NULL DEFAULT 0,
        finding_count INTEGER NOT NULL DEFAULT 0,
        path_count INTEGER NOT NULL DEFAULT 0,
        risk_score REAL,
        summary TEXT
      );
      CREATE TABLE IF NOT EXISTS findings (
        run_id TEXT NOT NULL,
        id TEXT NOT NULL,
        source TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        resource_json TEXT NOT NULL,
        raw_json TEXT,
        reachable INTEGER,
        exploit_score REAL,
        attack_path_id TEXT,
        controls_json TEXT,
        base_score REAL,
        observed_at TEXT,
        PRIMARY KEY (run_id, id),
        FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
      CREATE TABLE IF NOT EXISTS inventories (
        run_id TEXT PRIMARY KEY,
        json TEXT NOT NULL,
        FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS attack_paths (
        run_id TEXT NOT NULL,
        id TEXT NOT NULL,
        narrative TEXT NOT NULL,
        score REAL NOT NULL,
        entry_point TEXT,
        steps_json TEXT NOT NULL,
        finding_ids_json TEXT NOT NULL,
        PRIMARY KEY (run_id, id),
        FOREIGN KEY (run_id) REFERENCES runs(id) ON DELETE CASCADE
      );
    `);
  }

  createRun(run: Pick<RunRecord, 'id' | 'engine'>): void {
    this.db
      .prepare('INSERT INTO runs (id, created_at, status, engine) VALUES (?, ?, ?, ?)')
      .run(run.id, new Date().toISOString(), 'running', run.engine);
  }

  finishRun(
    id: string,
    patch: Partial<Pick<RunRecord, 'status' | 'usedFixtures' | 'findingCount' | 'pathCount' | 'riskScore' | 'summary'>>,
  ): void {
    this.db
      .prepare(
        `UPDATE runs SET status = COALESCE(?, status), used_fixtures = COALESCE(?, used_fixtures),
           finding_count = COALESCE(?, finding_count), path_count = COALESCE(?, path_count),
           risk_score = COALESCE(?, risk_score), summary = COALESCE(?, summary)
         WHERE id = ?`,
      )
      .run(
        patch.status ?? null,
        patch.usedFixtures === undefined ? null : patch.usedFixtures ? 1 : 0,
        patch.findingCount ?? null,
        patch.pathCount ?? null,
        patch.riskScore ?? null,
        patch.summary ?? null,
        id,
      );
  }

  saveFindings(runId: string, findings: Finding[]): void {
    const stmt = this.db.prepare(
      `INSERT OR REPLACE INTO findings
        (run_id, id, source, rule_id, title, description, severity, resource_json, raw_json,
         reachable, exploit_score, attack_path_id, controls_json, base_score, observed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );
    const tx = this.db.prepare('BEGIN');
    tx.run();
    try {
      for (const f of findings) {
        stmt.run(
          runId,
          f.id,
          f.source,
          f.ruleId,
          f.title,
          f.description ?? '',
          f.severity,
          JSON.stringify(f.resource),
          JSON.stringify(f.raw ?? null),
          f.reachable === undefined ? null : f.reachable ? 1 : 0,
          f.exploitScore ?? null,
          f.attackPathId ?? null,
          f.controls ? JSON.stringify(f.controls) : null,
          f.baseScore ?? null,
          f.observedAt ?? null,
        );
      }
      this.db.prepare('COMMIT').run();
    } catch (err) {
      this.db.prepare('ROLLBACK').run();
      throw err;
    }
  }

  saveInventory(runId: string, inventory: ClusterInventory): void {
    this.db
      .prepare('INSERT OR REPLACE INTO inventories (run_id, json) VALUES (?, ?)')
      .run(runId, JSON.stringify(inventory));
  }

  saveAttackPaths(runId: string, paths: AttackPath[]): void {
    const stmt = this.db.prepare(
      `INSERT OR REPLACE INTO attack_paths
        (run_id, id, narrative, score, entry_point, steps_json, finding_ids_json)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    );
    for (const p of paths) {
      stmt.run(
        runId,
        p.id,
        p.narrative,
        p.score,
        p.entryPoint ?? null,
        JSON.stringify(p.steps),
        JSON.stringify(p.findingIds),
      );
    }
  }

  getRun(id: string): RunRecord | undefined {
    const row = this.db.prepare('SELECT * FROM runs WHERE id = ?').get(id) as unknown as
      | RawRun
      | undefined;
    return row ? toRunRecord(row) : undefined;
  }

  listRuns(limit = 50): RunRecord[] {
    const rows = this.db
      .prepare('SELECT * FROM runs ORDER BY created_at DESC LIMIT ?')
      .all(limit) as unknown as RawRun[];
    return rows.map(toRunRecord);
  }

  getFindings(runId: string): Finding[] {
    const rows = this.db
      .prepare('SELECT * FROM findings WHERE run_id = ?')
      .all(runId) as unknown as RawFinding[];
    return rows.map(toFinding);
  }

  getInventory(runId: string): ClusterInventory | undefined {
    const row = this.db.prepare('SELECT json FROM inventories WHERE run_id = ?').get(runId) as
      | unknown as { json: string } | undefined;
    return row ? (JSON.parse(row.json) as ClusterInventory) : undefined;
  }

  getAttackPaths(runId: string): AttackPath[] {
    const rows = this.db
      .prepare('SELECT * FROM attack_paths WHERE run_id = ? ORDER BY score DESC')
      .all(runId) as unknown as RawPath[];
    return rows.map((r) => ({
      id: r.id,
      narrative: r.narrative,
      score: r.score,
      entryPoint: r.entry_point ?? undefined,
      steps: JSON.parse(r.steps_json),
      findingIds: JSON.parse(r.finding_ids_json),
    }));
  }

  close(): void {
    this.db.close();
  }
}

interface RawRun {
  id: string;
  created_at: string;
  status: string;
  engine: string;
  used_fixtures: number;
  finding_count: number;
  path_count: number;
  risk_score: number | null;
  summary: string | null;
}
interface RawFinding {
  id: string;
  source: string;
  rule_id: string;
  title: string;
  description: string | null;
  severity: string;
  resource_json: string;
  raw_json: string | null;
  reachable: number | null;
  exploit_score: number | null;
  attack_path_id: string | null;
  controls_json: string | null;
  base_score: number | null;
  observed_at: string | null;
}
interface RawPath {
  id: string;
  narrative: string;
  score: number;
  entry_point: string | null;
  steps_json: string;
  finding_ids_json: string;
}

function toRunRecord(r: RawRun): RunRecord {
  return {
    id: r.id,
    createdAt: r.created_at,
    status: r.status as RunStatus,
    engine: r.engine,
    usedFixtures: Boolean(r.used_fixtures),
    findingCount: r.finding_count,
    pathCount: r.path_count,
    riskScore: r.risk_score,
    summary: r.summary,
  };
}

function toFinding(r: RawFinding): Finding {
  return {
    id: r.id,
    source: r.source as Finding['source'],
    ruleId: r.rule_id,
    title: r.title,
    description: r.description ?? '',
    severity: r.severity as Finding['severity'],
    resource: JSON.parse(r.resource_json),
    raw: r.raw_json ? JSON.parse(r.raw_json) : null,
    reachable: r.reachable === null ? undefined : Boolean(r.reachable),
    exploitScore: r.exploit_score ?? undefined,
    attackPathId: r.attack_path_id ?? undefined,
    controls: r.controls_json ? JSON.parse(r.controls_json) : undefined,
    baseScore: r.base_score ?? undefined,
    observedAt: r.observed_at ?? undefined,
  };
}
