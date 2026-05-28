import type { NextAuthConfig } from 'next-auth';
import Google from 'next-auth/providers/google';
import GitHub from 'next-auth/providers/github';
import MicrosoftEntraID from 'next-auth/providers/microsoft-entra-id';
import Credentials from 'next-auth/providers/credentials';

const has = (...keys: string[]) => keys.every((k) => Boolean(process.env[k]));

/** Which SSO providers are configured (drives both NextAuth and the login UI). */
export function configuredProviders(): Array<'google' | 'github' | 'microsoft-entra-id' | 'dev'> {
  const out: Array<'google' | 'github' | 'microsoft-entra-id' | 'dev'> = [];
  if (has('AUTH_GOOGLE_ID', 'AUTH_GOOGLE_SECRET')) out.push('google');
  if (has('AUTH_GITHUB_ID', 'AUTH_GITHUB_SECRET')) out.push('github');
  if (has('AUTH_MICROSOFT_ENTRA_ID_ID', 'AUTH_MICROSOFT_ENTRA_ID_SECRET')) {
    out.push('microsoft-entra-id');
  }
  if (process.env.AUTH_DEV_LOGIN === '1') out.push('dev');
  return out;
}

/** Auth is "on" only when a secret + at least one real provider exist. */
export function authEnabled(): boolean {
  return Boolean(process.env.AUTH_SECRET) && configuredProviders().length > 0;
}

function providers() {
  const p = [];
  const c = configuredProviders();
  if (c.includes('google')) p.push(Google);
  if (c.includes('github')) p.push(GitHub);
  if (c.includes('microsoft-entra-id')) p.push(MicrosoftEntraID);
  if (c.includes('dev')) {
    // Local-only shortcut so the flow is testable without OAuth apps.
    p.push(
      Credentials({
        id: 'dev',
        name: 'Dev login',
        credentials: { email: { label: 'Email', type: 'email' } },
        authorize: (creds) => {
          const email = typeof creds?.email === 'string' ? creds.email : '';
          return email ? { email, name: email.split('@')[0] } : null;
        },
      }),
    );
  }
  return p;
}

/**
 * Edge-safe config (no DB, no node-only imports) — shared by the middleware and
 * the full server config. The `authorized` callback gates routes using only
 * token claims populated by the jwt callback in auth.ts.
 */
export const authConfig = {
  providers: providers(),
  session: { strategy: 'jwt' },
  trustHost: true,
  pages: { signIn: '/login' },
  callbacks: {
    // Pure (no DB) — maps the JWT claims onto the session. Lives here so the
    // edge middleware sees role/MFA claims too (the DB-backed jwt callback that
    // sets these is in auth.ts).
    session({ session, token }) {
      const t = token as {
        uid?: string;
        activeRole?: string;
        maxRole?: string;
        mfaRequired?: boolean;
        mfaEnrolled?: boolean;
        activeAccountId?: string | null;
      };
      Object.assign(session.user, {
        id: t.uid ?? null,
        role: t.activeRole ?? null,
        maxRole: t.maxRole ?? 'viewer',
        mfaRequired: Boolean(t.mfaRequired),
        mfaEnrolled: Boolean(t.mfaEnrolled),
        activeAccountId: t.activeAccountId ?? null,
      });
      return session;
    },
    authorized({ auth, request }) {
      // Demo mode (no secret/providers configured): leave the app open so the
      // hosted preview works without auth. Enabling auth turns the gate on.
      if (!authEnabled()) return true;

      const { pathname } = request.nextUrl;
      // Public paths always allowed. `/api/agent/*` and the pubkey-connect
      // CLI endpoints (`/api/scans`, `/api/clusters/:id/events`) are
      // machine-to-machine, authenticated by install / enrollment token in
      // the route itself — they must NOT be behind the user-session gate.
      // (`POST /api/clusters` IS session-auth'd; it stays under the gate.)
      if (
        pathname.startsWith('/login') ||
        pathname.startsWith('/api/auth') ||
        pathname.startsWith('/api/agent') ||
        pathname.startsWith('/api/scans') ||
        /^\/api\/clusters\/[^/]+\/events\/?$/.test(pathname) ||
        pathname.startsWith('/mfa')
      ) {
        return true;
      }
      if (!auth?.user) return false; // → redirect to signIn

      // MFA gate: approver/admin must be enrolled before reaching app pages.
      const u = auth.user as { mfaRequired?: boolean; mfaEnrolled?: boolean };
      if (u.mfaRequired && !u.mfaEnrolled) {
        const url = request.nextUrl.clone();
        url.pathname = '/mfa';
        return Response.redirect(url);
      }
      return true;
    },
  },
} satisfies NextAuthConfig;
