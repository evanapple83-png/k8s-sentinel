import { redirect } from 'next/navigation';
import { KeyRound } from 'lucide-react';
import { auth, unstable_update } from '@/auth';
import { authEnabled } from '@/auth.config';
import { getMfaState, markMfaEnrolled, setMfaSecret } from '@/lib/data';
import { generateSecret, otpauthUri, verifyTotp } from '@/lib/totp';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

export const dynamic = 'force-dynamic';

export default async function MfaPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string }>;
}) {
  if (!authEnabled()) redirect('/');
  const session = await auth();
  const userId = session?.user?.id;
  const email = session?.user?.email ?? 'account';
  if (!userId) redirect('/login');

  // Reuse an existing pending secret or mint one for this enrollment.
  const state = await getMfaState(userId);
  if (state.enrolled) redirect('/');
  let secret = state.secret;
  if (!secret) {
    secret = generateSecret();
    await setMfaSecret(userId, secret);
  }
  const uri = otpauthUri(secret, email);
  const { error } = await searchParams;

  async function verify(formData: FormData) {
    'use server';
    const code = String(formData.get('code') ?? '');
    const current = await getMfaState(userId!);
    if (!current.secret || !verifyTotp(current.secret, code)) {
      redirect('/mfa?error=1');
    }
    await markMfaEnrolled(userId!, email);
    await unstable_update({}); // refresh JWT claims (mfaEnrolled → true)
    redirect('/');
  }

  return (
    <div className="grid min-h-dvh place-items-center p-6">
      <Card className="w-full max-w-md">
        <CardHeader className="items-center text-center">
          <span className="mb-2 grid size-11 place-items-center rounded-xl bg-primary text-primary-foreground">
            <KeyRound className="size-6" />
          </span>
          <CardTitle>Set up two-factor authentication</CardTitle>
          <p className="text-sm text-muted-foreground">
            Required for approver and admin roles. Add this secret to an authenticator app (Google
            Authenticator, 1Password, Authy), then enter the 6-digit code.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1 rounded-lg border bg-muted/40 p-3 text-center">
            <div className="text-xs uppercase tracking-wide text-muted-foreground">Secret key</div>
            <code className="select-all break-all font-mono text-sm">{secret}</code>
          </div>
          <details className="text-xs text-muted-foreground">
            <summary className="cursor-pointer">Show otpauth URI</summary>
            <code className="mt-1 block break-all font-mono">{uri}</code>
          </details>

          <form action={verify} className="space-y-2">
            <Input
              name="code"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="123456"
              maxLength={6}
              required
              className="text-center text-lg tracking-[0.4em]"
            />
            {error ? (
              <p role="alert" className="text-sm text-destructive">
                That code didn&apos;t match. Try the current code from your app.
              </p>
            ) : null}
            <Button type="submit" className="w-full">
              Verify &amp; enable
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
