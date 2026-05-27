import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { analyzeReachability, answerQuery } from '@k8s-sentinel/agent-analyst';
import { silenceExperimentalWarnings } from './util/warnings.js';
import { loadConfig, type SentinelConfig } from './config.js';
import { runScan } from './orchestrator.js';
import { SqliteStore } from './store.js';
import {
  approveFix,
  approvedFixIds,
  auditSink,
  loadRun,
  proposalsForRun,
  renderReport,
  reportForRun,
  type ReportFormat,
} from './reporting.js';

/**
 * K8s Sentinel orchestrator API. A small, dependency-free HTTP + SSE server
 * (node:http) that drives scans and serves the run/posture/report/fix data to
 * the dashboard. Read-only over the cluster; the only state it writes is the
 * local run store, the audit log, and reviewable PR bundles on disk. Nothing is
 * ever applied to a cluster from here (BUILD.md §10).
 */

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json', ...CORS });
  res.end(payload);
}

function notFound(res: ServerResponse, message = 'not found'): void {
  sendJson(res, 404, { error: message });
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return {};
  }
}

function withStore<T>(config: SentinelConfig, fn: (store: SqliteStore) => T): T {
  const store = new SqliteStore(config.dbPath);
  try {
    return fn(store);
  } finally {
    store.close();
  }
}

export function createServer(config: SentinelConfig): Server {
  return createHttpServer((req, res) => {
    handle(req, res, config).catch((err) => {
      sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) });
    });
  });
}

async function handle(req: IncomingMessage, res: ServerResponse, config: SentinelConfig): Promise<void> {
  const method = req.method ?? 'GET';
  if (method === 'OPTIONS') {
    res.writeHead(204, CORS);
    res.end();
    return;
  }

  const url = new URL(req.url ?? '/', 'http://localhost');
  const seg = url.pathname.split('/').filter(Boolean); // ["api", "runs", ...]
  if (seg[0] !== 'api') return notFound(res);

  // GET /api/health
  if (method === 'GET' && seg[1] === 'health') {
    return sendJson(res, 200, { ok: true, engine: config.engine, service: 'k8s-sentinel' });
  }

  // GET /api/scan/stream  — SSE scan run
  if (method === 'GET' && seg[1] === 'scan' && seg[2] === 'stream') {
    return scanStream(res, config, {
      namespace: url.searchParams.get('namespace') ?? undefined,
      kubeconfig: url.searchParams.get('kubeconfig') ?? undefined,
    });
  }

  // POST /api/scan  — run scan, return summary
  if (method === 'POST' && seg[1] === 'scan' && seg.length === 2) {
    const body = (await readBody(req)) as { namespace?: string; kubeconfig?: string };
    const summary = await runScan({ config, target: { namespace: body.namespace, kubeconfig: body.kubeconfig } });
    return sendJson(res, 200, {
      runId: summary.run.id,
      riskScore: summary.run.riskScore,
      summary: summary.run.summary,
      findingCount: summary.findings.length,
      pathCount: summary.paths.length,
      proposalCount: summary.proposals.length,
    });
  }

  // POST /api/ask  — plain-English query
  if (method === 'POST' && seg[1] === 'ask' && seg.length === 2) {
    const body = (await readBody(req)) as { query?: string; runId?: string };
    return ask(res, config, body);
  }

  // POST /api/fixes/:id/approve
  if (method === 'POST' && seg[1] === 'fixes' && seg[3] === 'approve' && seg[2]) {
    const body = (await readBody(req)) as { runId?: string };
    return approve(res, config, decodeURIComponent(seg[2]), body.runId);
  }

  // GET /api/runs ...
  if (method === 'GET' && seg[1] === 'runs') {
    return getRuns(res, config, seg.slice(2), url);
  }

  return notFound(res);
}

function scanStream(
  res: ServerResponse,
  config: SentinelConfig,
  target: { namespace?: string; kubeconfig?: string },
): void {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    ...CORS,
  });
  const send = (event: string, data: unknown): void => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };
  send('start', { engine: config.engine });

  runScan({ config, target, onProgress: (message) => send('progress', { message }) })
    .then((summary) => {
      send('done', {
        runId: summary.run.id,
        riskScore: summary.run.riskScore,
        summary: summary.run.summary,
        usedFixtures: summary.run.usedFixtures,
        findingCount: summary.findings.length,
        pathCount: summary.paths.length,
        proposalCount: summary.proposals.length,
      });
      res.end();
    })
    .catch((err) => {
      send('error', { message: err instanceof Error ? err.message : String(err) });
      res.end();
    });
}

async function getRuns(res: ServerResponse, config: SentinelConfig, rest: string[], url: URL): Promise<void> {
  // GET /api/runs
  if (rest.length === 0) {
    const runs = withStore(config, (s) => s.listRuns());
    return sendJson(res, 200, { runs });
  }

  const runId = decodeURIComponent(rest[0]!);
  const sub = rest[1];

  // GET /api/runs/:id/audit
  if (sub === 'audit') {
    const entries = await auditSink().list(runId);
    const verify = url.searchParams.get('verify') !== null ? await auditSink().verify() : undefined;
    return sendJson(res, 200, { runId, entries, verify });
  }

  const bundle = withStore(config, (s) => loadRun(s, runId));
  if (!bundle) return notFound(res, `run ${runId} not found`);

  // GET /api/runs/:id/report?format=
  if (sub === 'report') {
    const fmt = (url.searchParams.get('format') ?? 'md') as ReportFormat;
    const { body, contentType, ext } = renderReport(reportForRun(bundle), fmt);
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Disposition': `inline; filename="sentinel-${runId}.${ext}"`,
      ...CORS,
    });
    res.end(typeof body === 'string' ? body : Buffer.from(body));
    return;
  }

  // GET /api/runs/:id/fixes
  if (sub === 'fixes') {
    const approved = await approvedFixIds(runId);
    const fixes = proposalsForRun(bundle).map((p) => ({ ...p, approved: approved.has(p.id) }));
    return sendJson(res, 200, { runId, fixes });
  }

  if (sub === 'findings') return sendJson(res, 200, { runId, findings: bundle.findings });
  if (sub === 'paths') return sendJson(res, 200, { runId, paths: bundle.paths });

  // GET /api/runs/:id  — full snapshot for the Overview screen
  if (!sub) {
    const approved = await approvedFixIds(runId);
    return sendJson(res, 200, {
      run: bundle.run,
      findings: bundle.findings,
      paths: bundle.paths,
      fixes: proposalsForRun(bundle).map((p) => ({ ...p, approved: approved.has(p.id) })),
    });
  }

  return notFound(res);
}

async function ask(
  res: ServerResponse,
  config: SentinelConfig,
  body: { query?: string; runId?: string },
): Promise<void> {
  const query = (body.query ?? '').trim();
  if (!query) return sendJson(res, 400, { error: 'query required' });

  const result = withStore(config, (store) => {
    const runId = body.runId ?? store.listRuns(1)[0]?.id;
    const inventory = runId ? store.getInventory(runId) : undefined;
    if (!runId || !inventory) return undefined;
    const findings = store.getFindings(runId);
    const { contexts } = analyzeReachability(findings, inventory);
    const answer = answerQuery(query, {
      findings,
      paths: store.getAttackPaths(runId),
      contexts,
      namespaces: inventory.namespaces,
    });
    return { runId, answer };
  });

  if (!result) return sendJson(res, 404, { error: 'no analysed run found' });
  return sendJson(res, 200, result);
}

async function approve(
  res: ServerResponse,
  config: SentinelConfig,
  fixId: string,
  runId?: string,
): Promise<void> {
  const resolvedRun = runId ?? withStore(config, (s) => s.listRuns(1)[0]?.id);
  if (!resolvedRun) return sendJson(res, 404, { error: 'no run found' });

  const store = new SqliteStore(config.dbPath);
  let result;
  try {
    result = await approveFix({ store, runId: resolvedRun, fixId, actor: 'user' });
  } finally {
    store.close();
  }
  if (!result) return notFound(res, `fix ${fixId} not found in run ${resolvedRun}`);

  return sendJson(res, 200, {
    approved: result.proposalId,
    branch: result.bundle.branch,
    bundleDir: result.dir,
    files: result.bundle.files.length,
    note: 'Reviewable PR bundle written to disk. Nothing was applied to your cluster.',
  });
}

function main(): void {
  silenceExperimentalWarnings();
  const config = loadConfig();
  const server = createServer(config);
  server.listen(config.apiPort, () => {
    console.log(`K8s Sentinel API on http://localhost:${config.apiPort} (engine: ${config.engine})`);
    console.log('  GET  /api/health');
    console.log('  GET  /api/scan/stream          (SSE: live scan)');
    console.log('  POST /api/scan');
    console.log('  GET  /api/runs · /api/runs/:id · /:id/findings · /:id/paths · /:id/fixes');
    console.log('  GET  /api/runs/:id/report?format=md|json|html|pdf');
    console.log('  GET  /api/runs/:id/audit[?verify]');
    console.log('  POST /api/fixes/:id/approve · POST /api/ask');
  });
}

// Run when invoked directly (tsx src/server.ts / node dist/server.js).
if (process.argv[1] && /server\.[tj]s$/.test(process.argv[1])) main();
