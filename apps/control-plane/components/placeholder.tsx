import type { ReactNode } from 'react';
import { Card, CardContent } from '@/components/ui/card';

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
