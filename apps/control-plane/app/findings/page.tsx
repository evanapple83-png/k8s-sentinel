import { EmptyState } from '@/components/placeholder';
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

  return <FindingsTable findings={findings} />;
}
