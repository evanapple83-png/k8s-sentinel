import { Github, ShieldCheck } from 'lucide-react';
import { signIn } from '@/auth';
import { authEnabled, configuredProviders } from '@/auth.config';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const LABELS: Record<string, string> = {
  google: 'Continue with Google',
  github: 'Continue with GitHub',
  'microsoft-entra-id': 'Continue with Microsoft',
};

export default function LoginPage() {
  const providers = configuredProviders();

  return (
    <div className="grid min-h-dvh place-items-center p-6">
      <Card className="w-full max-w-sm">
        <CardHeader className="items-center text-center">
          <span className="mb-2 grid size-11 place-items-center rounded-xl bg-primary text-primary-foreground">
            <ShieldCheck className="size-6" />
          </span>
          <CardTitle>Sign in to K8s Sentinel</CardTitle>
          <p className="text-sm text-muted-foreground">
            Hosted control plane for your clusters&apos; security posture.
          </p>
        </CardHeader>
        <CardContent className="space-y-3">
          {!authEnabled() ? (
            <div className="rounded-lg border border-dashed p-4 text-center text-sm text-muted-foreground">
              Auth isn&apos;t configured yet — the app is running in{' '}
              <span className="font-medium text-foreground">demo mode</span>. Set{' '}
              <code className="font-mono text-xs">AUTH_SECRET</code> and a provider to enable
              sign-in.
            </div>
          ) : null}

          {providers
            .filter((p) => p !== 'dev')
            .map((p) => (
              <form
                key={p}
                action={async () => {
                  'use server';
                  await signIn(p, { redirectTo: '/' });
                }}
              >
                <Button type="submit" variant="outline" className="w-full">
                  {p === 'github' ? <Github className="size-4" /> : null}
                  {LABELS[p] ?? `Continue with ${p}`}
                </Button>
              </form>
            ))}

          {providers.includes('dev') ? (
            <form
              action={async (formData: FormData) => {
                'use server';
                await signIn('dev', {
                  email: String(formData.get('email') ?? ''),
                  redirectTo: '/',
                });
              }}
              className="space-y-2 border-t pt-3"
            >
              <label className="text-xs font-medium text-muted-foreground">Dev login (local)</label>
              <Input name="email" type="email" placeholder="you@example.com" required />
              <Button type="submit" variant="secondary" className="w-full">
                Continue
              </Button>
            </form>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

export const dynamic = 'force-dynamic';
