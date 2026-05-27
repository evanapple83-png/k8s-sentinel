import type {
  ApproveResult,
  AskResult,
  AuditEntry,
  Fix,
  RunRecord,
  RunSnapshot,
} from './types';

/**
 * Thin client for the orchestrator API. Base URL comes from
 * NEXT_PUBLIC_API_BASE (default http://localhost:8787). All calls are
 * read-only except the explicit scan/approve actions.
 */
export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, '') ?? 'http://localhost:8787';

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} — ${path}`);
  return (await res.json()) as T;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText} — ${path}`);
  return (await res.json()) as T;
}

export const api = {
  health: () => getJson<{ ok: boolean; engine: string }>('/api/health'),
  runs: () => getJson<{ runs: RunRecord[] }>('/api/runs').then((r) => r.runs),
  run: (id: string) => getJson<RunSnapshot>(`/api/runs/${encodeURIComponent(id)}`),
  fixes: (id: string) =>
    getJson<{ fixes: Fix[] }>(`/api/runs/${encodeURIComponent(id)}/fixes`).then((r) => r.fixes),
  audit: (id: string) =>
    getJson<{ entries: AuditEntry[] }>(`/api/runs/${encodeURIComponent(id)}/audit`).then(
      (r) => r.entries,
    ),
  reportUrl: (id: string, format: 'md' | 'json' | 'html' | 'pdf') =>
    `${API_BASE}/api/runs/${encodeURIComponent(id)}/report?format=${format}`,
  ask: (query: string, runId?: string) => postJson<AskResult>('/api/ask', { query, runId }),
  approve: (fixId: string, runId: string) =>
    postJson<ApproveResult>(`/api/fixes/${encodeURIComponent(fixId)}/approve`, { runId }),
  scanStreamUrl: (namespace?: string) =>
    `${API_BASE}/api/scan/stream${namespace ? `?namespace=${encodeURIComponent(namespace)}` : ''}`,
};
