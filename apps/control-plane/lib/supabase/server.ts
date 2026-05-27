import 'server-only';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';

/**
 * Server-only Supabase client.
 *
 * Uses the SECRET key (`sb_secret_…`, or legacy `service_role`), which bypasses
 * RLS. This client must NEVER be imported into a browser bundle — the
 * `server-only` import makes that a build error. The browser never talks to
 * Supabase directly; all reads/writes go through Server Components / Route
 * Handlers that call the tenant-scoped data layer in `lib/data.ts`.
 */
let cached: SupabaseClient | null = null;

export function supabaseAdmin(): SupabaseClient {
  if (cached) return cached;

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const secret =
    process.env.SUPABASE_SECRET_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !secret) {
    throw new Error(
      'Supabase is not configured: set NEXT_PUBLIC_SUPABASE_URL and SUPABASE_SECRET_KEY (or SUPABASE_SERVICE_ROLE_KEY).',
    );
  }

  cached = createClient(url, secret, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return cached;
}

/** True when Supabase env is present — lets pages render a setup hint instead of crashing. */
export function supabaseConfigured(): boolean {
  return Boolean(
    process.env.NEXT_PUBLIC_SUPABASE_URL &&
      (process.env.SUPABASE_SECRET_KEY ?? process.env.SUPABASE_SERVICE_ROLE_KEY),
  );
}
