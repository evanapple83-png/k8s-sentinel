import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import { getAuthContext, provisionUser } from './lib/data';

/**
 * Full server-side NextAuth (Node runtime). Adds the DB-backed `jwt` callback
 * to the edge-safe `authConfig`. Used by the route handler and server
 * components; the middleware uses `authConfig` directly (no DB on the edge).
 */
export const { handlers, auth, signIn, signOut, unstable_update } = NextAuth({
  ...authConfig,
  callbacks: {
    ...authConfig.callbacks,
    async jwt({ token, user, trigger }) {
      // On sign-in: provision the user + load role/MFA into the token.
      if (user?.email) {
        try {
          const uid = await provisionUser({
            email: user.email,
            name: user.name,
            image: user.image,
          });
          applyContext(token, await getAuthContext(uid));
        } catch (err) {
          // Degrade gracefully if Supabase is unreachable: viewer, no MFA loop.
          console.error('[auth] provisioning failed:', err);
          token.maxRole = 'viewer';
          token.mfaRequired = false;
          token.mfaEnrolled = true;
        }
      } else if (trigger === 'update' && typeof token.uid === 'string') {
        // e.g. after MFA enrollment — refresh claims from the DB.
        try {
          applyContext(token, await getAuthContext(token.uid));
        } catch (err) {
          console.error('[auth] refresh failed:', err);
        }
      }
      return token;
    },
  },
});

function applyContext(
  token: Record<string, unknown>,
  ctx: Awaited<ReturnType<typeof getAuthContext>>,
): void {
  token.uid = ctx.userId;
  token.maxRole = ctx.maxRole;
  token.mfaRequired = ctx.mfaRequired;
  token.mfaEnrolled = ctx.mfaEnrolled;
  token.activeAccountId = ctx.activeAccountId;
  token.activeRole = ctx.activeRole;
}
