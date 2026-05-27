import type { ReactNode } from 'react';
import Link from 'next/link';
import { PlugZap } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { buttonVariants } from '@/components/ui/button';
import { cn } from '@/lib/utils';

/**
 * Calm empty state for live mode when an account/cluster has no scan data yet.
 * Keeps the data-dense §8 frame (header + card) but points at /connect.
 */
export function EmptyState({
  title,
  description,
  message = 'No scan data yet for this cluster.',
}: {
  title: string;
  description: string;
  message?: string;
}) {
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
      </header>
      <Card>
        <CardContent className="flex flex-col items-center gap-4 p-12 text-center">
          <span className="grid size-12 place-items-center rounded-full bg-muted text-muted-foreground">
            <PlugZap className="size-6" />
          </span>
          <div className="space-y-1">
            <div className="text-sm font-medium">{message}</div>
            <p className="max-w-sm text-sm text-muted-foreground">
              Connect a cluster and run a scan — findings, attack paths, and fixes
              appear here automatically.
            </p>
          </div>
          <Link href="/connect" className={cn(buttonVariants({ size: 'sm' }))}>
            <PlugZap className="size-4" /> Connect a cluster
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}

/** Lightweight screen stub used while a route's data layer is being wired. */
export function Placeholder({
  title,
  description,
  note,
  children,
}: {
  title: string;
  description: string;
  note?: string;
  children?: ReactNode;
}) {
  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <p className="text-sm text-muted-foreground">{description}</p>
      </header>
      {children ?? (
        <Card>
          <CardContent className="p-8 text-sm text-muted-foreground">
            {note ?? 'Connect a cluster to populate this screen.'}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
