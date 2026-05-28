import { EmptyState } from '@/components/placeholder';
import { FEATURE_AI_NARRATION } from '@/lib/flags';
import { getActiveData, type SearchParamsInput } from '@/lib/active';
import { AskClient } from './ask-client';
import { AskAiClient } from './ask-ai-client';

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

  // AI-powered Ask: requires the flag AND live tenant context. In demo mode
  // (no real cluster) we fall back to the offline keyword matcher so the
  // hosted preview keeps working end-to-end without an Anthropic key.
  if (
    FEATURE_AI_NARRATION &&
    !data.demo &&
    data.activeAccountId &&
    data.activeClusterId
  ) {
    return (
      <AskAiClient
        accountId={data.activeAccountId}
        clusterId={data.activeClusterId}
        scannedAt={data.snapshot.run.createdAt}
      />
    );
  }

  return <AskClient findings={findings} />;
}
