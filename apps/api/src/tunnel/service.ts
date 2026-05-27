import { analyzeReachability, answerQuery } from '@k8s-sentinel/agent-analyst';
import type { SentinelConfig } from '../config.js';
import { runScan } from '../orchestrator.js';
import { SqliteStore } from '../store.js';
import { approveFix, auditSink, loadRun, renderReport, reportForRun, type ReportFormat } from '../reporting.js';
import { toPostureSnapshot } from './wire.js';
import type { TunnelHandlers } from './client.js';

/**
 * Wire the tunnel's down-commands to the SAME orchestrator/reporting paths the
 * SSE server uses, so hosted (hybrid) and in-cluster behaviour never diverge.
 * Read-only + propose-only is preserved: scan/ask/report read posture; approve
 * writes a reviewable PR bundle to disk and applies nothing to the cluster.
 */
export function buildTunnelHandlers(config: SentinelConfig): TunnelHandlers {
  return {
    async scan(params, emit) {
      const target = {
        namespace: typeof params.namespace === 'string' ? params.namespace : undefined,
        kubeconfig: typeof params.kubeconfig === 'string' ? params.kubeconfig : undefined,
      };
      const summary = await runScan({
        config,
        target,
        onProgress: (message) => emit({ type: 'progress', message }),
      });
      const audit = await auditSink().list(summary.run.id);
      return toPostureSnapshot({
        run: summary.run,
        findings: summary.findings,
        paths: summary.paths,
        proposals: summary.proposals,
        audit,
      });
    },

    async ask(query) {
      const trimmed = query.trim();
      if (!trimmed) throw new Error('query required');
      const store = new SqliteStore(config.dbPath);
      try {
        const runId = store.listRuns(1)[0]?.id;
        const inventory = runId ? store.getInventory(runId) : undefined;
        if (!runId || !inventory) throw new Error('no analysed run found');
        const findings = store.getFindings(runId);
        const { contexts } = analyzeReachability(findings, inventory);
        const answer = answerQuery(trimmed, {
          findings,
          paths: store.getAttackPaths(runId),
          contexts,
          namespaces: inventory.namespaces,
        });
        return { runId, answer };
      } finally {
        store.close();
      }
    },

    async approve(fixId, runId) {
      const store = new SqliteStore(config.dbPath);
      try {
        const resolvedRun = runId ?? store.listRuns(1)[0]?.id;
        if (!resolvedRun) throw new Error('no run found');
        const result = await approveFix({ store, runId: resolvedRun, fixId, actor: 'user' });
        if (!result) throw new Error(`fix ${fixId} not found in run ${resolvedRun}`);
        return {
          approved: result.proposalId,
          branch: result.bundle.branch,
          bundleDir: result.dir,
          files: result.bundle.files.length,
          note: 'Reviewable PR bundle written to disk. Nothing was applied to your cluster.',
        };
      } finally {
        store.close();
      }
    },

    async report(format, runId) {
      const store = new SqliteStore(config.dbPath);
      try {
        const resolvedRun = runId ?? store.listRuns(1)[0]?.id;
        if (!resolvedRun) throw new Error('no run found');
        const bundle = loadRun(store, resolvedRun);
        if (!bundle) throw new Error(`run ${resolvedRun} not found`);
        const { body, contentType, ext } = renderReport(reportForRun(bundle), format as ReportFormat);
        const bytes = typeof body === 'string' ? Buffer.byteLength(body) : body.byteLength;
        // The report body itself isn't shipped over a command frame; the hosted
        // plane fetches it on demand. We return its metadata.
        return { runId: resolvedRun, format: ext, contentType, bytes };
      } finally {
        store.close();
      }
    },
  };
}
