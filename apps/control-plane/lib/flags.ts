import 'server-only';

/**
 * Feature flags. Read from env at module-eval time so a flipped flag needs a
 * deploy/restart — explicit, auditable, and impossible to toggle from inside
 * a single request.
 *
 * Convention: a flag is "on" only for `1` / `true` / `on` (case-insensitive).
 * Anything else (including missing) is off. Matches docs/PUBKEY_CONNECT_CONTRACT.md §6.
 */

function readBool(name: string): boolean {
  const raw = (process.env[name] ?? '').trim().toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'on';
}

/** Public-key connect method (the new tab on /connect + its API routes). */
export const FEATURE_PUBKEY_CONNECT = readBool('FEATURE_PUBKEY_CONNECT');
