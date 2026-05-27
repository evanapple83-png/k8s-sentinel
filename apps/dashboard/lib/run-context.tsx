'use client';

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react';
import { api } from './api';
import type { RunRecord, RunSnapshot } from './types';

interface RunCtx {
  runs: RunRecord[];
  runId: string | null;
  setRunId: (id: string) => void;
  reload: () => Promise<void>;
  loading: boolean;
  error: string | null;
}

const Ctx = createContext<RunCtx | null>(null);
const STORAGE_KEY = 'sentinel.run';

export function useRuns(): RunCtx {
  const c = useContext(Ctx);
  if (!c) throw new Error('useRuns must be used within RunProvider');
  return c;
}

export function RunProvider({ children }: { children: ReactNode }) {
  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [runId, setRunIdState] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.runs();
      setRuns(list);
      setRunIdState((prev) => {
        if (prev && list.some((r) => r.id === prev)) return prev;
        const saved = typeof window !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null;
        if (saved && list.some((r) => r.id === saved)) return saved;
        return list[0]?.id ?? null;
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const setRunId = useCallback((id: string) => {
    setRunIdState(id);
    if (typeof window !== 'undefined') localStorage.setItem(STORAGE_KEY, id);
  }, []);

  return (
    <Ctx.Provider value={{ runs, runId, setRunId, reload, loading, error }}>
      {children}
    </Ctx.Provider>
  );
}

/** Load the full snapshot (run + findings + paths + fixes) for the active run. */
export function useSnapshot(): { data: RunSnapshot | null; loading: boolean; error: string | null } {
  const { runId } = useRuns();
  const [data, setData] = useState<RunSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!runId) {
      setData(null);
      return;
    }
    let active = true;
    setLoading(true);
    setError(null);
    api
      .run(runId)
      .then((d) => active && setData(d))
      .catch((e) => active && setError(e instanceof Error ? e.message : String(e)))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [runId]);

  return { data, loading, error };
}
