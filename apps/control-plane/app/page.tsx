import Link from 'next/link';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button, buttonVariants } from '@/components/ui/button';
import { RiskRing } from '@/components/risk-ring';

export default function OverviewPage() {
  return (
    <div className="mx-auto max-w-6xl space-y-7">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="text-sm text-muted-foreground">
            Posture for the selected cluster. Data is streamed up from the in-cluster agent.
          </p>
        </div>
        <Button variant="outline" disabled>
          Run scan
        </Button>
      </header>

      <div className="grid gap-5 md:grid-cols-[auto_1fr]">
        <Card className="grid place-items-center p-8">
          <RiskRing value={0} />
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>No cluster connected yet</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4 text-sm text-muted-foreground">
            <p>
              Connect your first cluster to see ranked attack paths, findings, and reviewable fixes
              here. The agent runs read-only inside your cluster and dials out — no Ingress, no
              port-forward.
            </p>
            <div className="flex flex-wrap gap-2">
              <Badge variant="clear">read-only RBAC</Badge>
              <Badge variant="secondary">propose-only fixes</Badge>
              <Badge variant="secondary">immutable audit log</Badge>
            </div>
            <Link href="/connect" className={buttonVariants()}>
              Connect your cluster
            </Link>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        {[
          { k: 'Critical', v: '—', variant: 'critical' as const },
          { k: 'Reachable', v: '—', variant: 'warn' as const },
          { k: 'Attack paths', v: '—', variant: 'clear' as const },
        ].map((s) => (
          <Card key={s.k}>
            <CardContent className="flex items-center justify-between p-5">
              <span className="text-sm text-muted-foreground">{s.k}</span>
              <Badge variant={s.variant}>{s.v}</Badge>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
