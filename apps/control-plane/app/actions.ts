'use server';

import { signOut } from '@/auth';

export async function doSignOut(): Promise<void> {
  await signOut({ redirectTo: '/login' });
}
