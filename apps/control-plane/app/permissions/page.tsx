import { Eye, Ban, ShieldCheck } from 'lucide-react';
import { auth } from '@/auth';
import { getActiveData, type SearchParamsInput } from '@/lib/active';
import {
  BASELINE_CANNOT,
  BASELINE_READS,
  CAPABILITIES,
  getCapabilities,
  type CapabilityState,
} from '@/lib/permissions';
import type { Role } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { PermissionsClient } from './permissions-client';

export const dynamic = 'force-dynamic';

const ROLE_RANK: Record<Role, number> = { viewer: 0, approver: 1, admin: 2 };

export default async function PermissionsPage({
  searchParams,
}: {
  searchParams?: SearchParamsInput;
}) {
  const data = await getActiveData(searchParams);

  let capabilities: CapabilityState[] = CAPABILITIES.map((c) => ({ ...c, enabled: false }));
  let clusterId = '';
  let live = false;
  let canEdit = false;

  if (!data.demo && data.activeClusterId && data.activeAccountId) {
    const session = await auth();
    const userId = session?.user?.id;
    if (userId) {
      try {
        capabilities = await getCapabilities(userId, data.activeAccountId, data.activeClusterId);
        clusterId = data.activeClusterId;
        live = true;
        const role = (session?.user?.role ?? session?.user?.maxRole ?? 'viewer') as Role;
        canEdit = ROLE_RANK[role] >= ROLE_RANK.admin;
      } catch {
        /* fall back to read-only catalog */
      }
    }
  }

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Permissions</h1>
        <p className="text-sm text-muted-foreground">
          What this agent can see, in plain English — and how to grant more. No YAML to write; every
          change is written to the audit log.
        </p>
      </header>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Eye className="size-4 text-primary" /> What the agent can see
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2.5">
          {BASELINE_READS.map((s) => (
            <div key={s.can} className="flex gap-3 text-sm">
              <ShieldCheck className="mt-0.5 size-4 shrink-0 text-clear" />
              <div>
                <span className="font-medium">{s.can}</span>{' '}
                <span className="text-muted-foreground">— {s.resources}</span>
                {s.note ? <div className="text-xs text-warn">{s.note}</div> : null}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Ban className="size-4 text-muted-foreground" /> What it cannot do
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {BASELINE_CANNOT.map((c) => (
            <div key={c} className="flex items-center gap-3 text-sm text-muted-foreground">
              <Ban className="size-3.5 shrink-0" /> {c}
            </div>
          ))}
        </CardContent>
      </Card>

      <PermissionsClient
        capabilities={capabilities}
        clusterId={clusterId}
        live={live}
        canEdit={canEdit}
      />
    </div>
  );
}
