import type { DefaultSession } from 'next-auth';
import type { Role } from '@/lib/types';

declare module 'next-auth' {
  interface Session {
    user: {
      id?: string | null;
      role?: Role | null;
      maxRole?: Role;
      mfaRequired?: boolean;
      mfaEnrolled?: boolean;
      activeAccountId?: string | null;
    } & DefaultSession['user'];
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    uid?: string;
    activeRole?: Role | null;
    maxRole?: Role;
    mfaRequired?: boolean;
    mfaEnrolled?: boolean;
    activeAccountId?: string | null;
  }
}
