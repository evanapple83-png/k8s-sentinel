import type { CSSProperties, ReactNode } from 'react';
import type { Severity } from '@/lib/types';

/** 0–100 → traffic-light bucket. green < 40, amber < 70, red ≥ 70. */
export function scoreBucket(score: number): 'crit' | 'warn' | 'ok' {
  return score >= 70 ? 'crit' : score >= 40 ? 'warn' : 'ok';
}

export function ringColor(score: number): string {
  const b = scoreBucket(score);
  return b === 'crit' ? 'var(--critical)' : b === 'warn' ? 'var(--warn)' : 'var(--clear)';
}

export function rating(score: number): string {
  return score >= 70 ? 'critical' : score >= 40 ? 'elevated' : score >= 20 ? 'moderate' : 'low';
}

export function RiskRing({ value, size = 132 }: { value: number; size?: number }) {
  const inner = Math.round(size * 0.8);
  const ringStyle = {
    '--ring-value': value,
    '--ring-color': ringColor(value),
    width: size,
    height: size,
  } as CSSProperties;
  return (
    <div className="ring" style={ringStyle}>
      <div className="inner" style={{ width: inner, height: inner }}>
        <span>{value}</span>
        <span className="of">/ 100</span>
      </div>
    </div>
  );
}

export function SevPill({ sev }: { sev: Severity }) {
  return <span className={`pill ${sev}`}>{sev}</span>;
}

export function Dot({ sev }: { sev: Severity }) {
  return <span className={`dot ${sev}`} />;
}

export function ResourceLabel({
  resource,
}: {
  resource: { kind: string; namespace?: string; name: string; image?: string };
}) {
  const ns = resource.namespace ? `${resource.namespace}/` : '';
  return (
    <span className="meta">
      {resource.kind} {ns}
      {resource.name}
      {resource.image ? ` · ${resource.image}` : ''}
    </span>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function PageHeader({ title, sub }: { title: string; sub?: string }) {
  return (
    <header>
      <h1 className="h1">{title}</h1>
      {sub ? <p className="sub">{sub}</p> : null}
    </header>
  );
}
