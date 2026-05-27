import { authEnabled } from '@/auth.config';
import { supabaseConfigured } from '@/lib/supabase/server';
import { helmInstallCommand } from '@/lib/install-tokens';
import { Card, CardContent } from '@/components/ui/card';
import { ConnectClient } from './connect-client';

export const dynamic = 'force-dynamic';

export default function ConnectPage() {
  const live = authEnabled() && supabaseConfigured();

  return (
    <div className="mx-auto max-w-2xl space-y-5">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Connect your cluster</h1>
        <p className="text-sm text-muted-foreground">
          One copy-paste Helm command installs the read-only agent. It dials out to the relay — no
          Ingress, no port-forward. Target: first results in under 5 minutes.
        </p>
      </header>

      {live ? (
        <ConnectClient />
      ) : (
        <Card>
          <CardContent className="space-y-3 p-6">
            <div className="rounded-md border border-dashed px-3 py-2 text-sm text-muted-foreground">
              Running in <span className="font-medium text-foreground">demo mode</span>. Sign in
              (configure auth + Supabase) to generate a real single-use install token and watch the
              cluster connect live.
            </div>
            <p className="text-sm text-muted-foreground">Representative command:</p>
            <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-4 text-[12px] leading-relaxed">
              <code className="font-mono">{helmInstallCommand('sk-install-DEMOxxxxexample')}</code>
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
