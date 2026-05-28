import { EmptyState } from '@/components/placeholder';
import { FEATURE_AI_NARRATION } from '@/lib/flags';
import { getActiveData, type SearchParamsInput } from '@/lib/active';
import { FindingsTable } from './findings-table';

export default async function FindingsPage({
  searchParams,
}: {
  searchParams?: SearchParamsInput;
}) {
  const data = await getActiveData(searchParams);
  const findings = data.snapshot?.findings ?? [];

  if (!data.snapshot || findings.length === 0) {
    return (
      <EmptyState
        title="Findings"
        description="Ranked by reachability-weighted exploitability — not raw CVSS."
        message="No findings yet for this cluster."
      />
    );
  }

  // AI narration is gated server-side; if the flag is off OR we're in demo
  // mode (no real accountId/clusterId to call the API with), the Explain
  // affordance is hidden from the rendered table.
  const aiContext =
    FEATURE_AI_NARRATION && !data.demo && data.activeAccountId && data.activeClusterId
      ? {
          accountId: data.activeAccountId,
          clusterId: data.activeClusterId,
          runId: data.snapshot.run.id,
        }
      : null;

  return <FindingsTable findings={findings} aiContext={aiContext} />;
}
