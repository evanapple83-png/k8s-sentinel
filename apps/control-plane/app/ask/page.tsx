import { EmptyState } from '@/components/placeholder';
import { getActiveData, type SearchParamsInput } from '@/lib/active';
import { AskClient } from './ask-client';

export default async function AskPage({
  searchParams,
}: {
  searchParams?: SearchParamsInput;
}) {
  const data = await getActiveData(searchParams);
  const findings = data.snapshot?.findings ?? [];

  if (!data.snapshot || findings.length === 0) {
    return (
      <EmptyState
        title="Ask"
        description="Plain-English questions over your posture graph."
        message="No scan data yet to ask about."
      />
    );
  }

  return <AskClient findings={findings} />;
}
