import { auth } from '@/auth';
import { EmptyState } from '@/components/placeholder';
import { getActiveData, type SearchParamsInput } from '@/lib/active';
import type { Role } from '@/lib/types';
import { FixesList } from './fixes-list';

const ROLE_RANK: Record<Role, number> = { viewer: 0, approver: 1, admin: 2 };

export default async function FixesPage({
  searchParams,
}: {
  searchParams?: SearchParamsInput;
}) {
  const data = await getActiveData(searchParams);
  const fixes = data.snapshot?.fixes ?? [];

  if (!data.snapshot || fixes.length === 0) {
    return (
      <EmptyState
        title="Fixes"
        description="Reachability-ranked, reviewable remediations. Approving opens a PR — the agent never applies changes in-cluster."
        message="No remediation proposals yet for this run."
      />
    );
  }

  // Demo mode is freely approvable (local toggle). Live mode requires approver+.
  let canApprove = true;
  if (!data.demo) {
    const session = await auth();
    const role = (session?.user?.role ?? session?.user?.maxRole ?? 'viewer') as Role;
    canApprove = ROLE_RANK[role] >= ROLE_RANK.approver;
  }

  return (
    <FixesList
      fixes={fixes}
      runId={data.snapshot.run.id}
      demo={data.demo}
      canApprove={canApprove}
    />
  );
}
