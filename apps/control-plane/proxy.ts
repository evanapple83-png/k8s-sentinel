import NextAuth from 'next-auth';
import { authConfig } from './auth.config';

/**
 * Route gate (Next 16 "proxy" convention, formerly middleware). The
 * `authorized` callback in authConfig short-circuits to "open" when auth isn't
 * configured (demo mode), so this is a no-op there and enforces sign-in + MFA
 * once AUTH_SECRET and a provider are set.
 */
export default NextAuth(authConfig).auth;

export const config = {
  // Run on everything except Next internals and static asset files.
  matcher: ['/((?!_next/static|_next/image|favicon.ico|.*\\.[\\w]+$).*)'],
};
