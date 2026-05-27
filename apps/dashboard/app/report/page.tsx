'use client';

import { api } from '@/lib/api';
import { useRuns } from '@/lib/run-context';
import { Empty, PageHeader } from '@/components/ui';

export default function ReportPage() {
  const { runId } = useRuns();

  if (!runId) {
    return (
      <>
        <PageHeader title="Report" />
        <Empty>No run selected. Run a scan on the Overview screen.</Empty>
      </>
    );
  }

  return (
    <>
      <PageHeader title="Report" sub="Audit-ready — read inline, export as PDF, Markdown, or JSON." />

      <div className="toolbar">
        <a className="btn primary" href={api.reportUrl(runId, 'pdf')} target="_blank" rel="noreferrer">
          Export PDF
        </a>
        <a className="btn" href={api.reportUrl(runId, 'md')} target="_blank" rel="noreferrer">
          Markdown
        </a>
        <a className="btn" href={api.reportUrl(runId, 'json')} target="_blank" rel="noreferrer">
          JSON
        </a>
      </div>

      <iframe className="report-frame" src={api.reportUrl(runId, 'html')} title="Security report" />
    </>
  );
}
