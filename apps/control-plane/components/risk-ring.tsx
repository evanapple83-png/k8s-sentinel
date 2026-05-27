import type { CSSProperties } from 'react';

/** 0–100 → traffic-light bucket. green < 40, amber < 70, red ≥ 70. */
export function scoreBucket(score: number): 'critical' | 'warn' | 'clear' {
  return score >= 70 ? 'critical' : score >= 40 ? 'warn' : 'clear';
}

export function rating(score: number): string {
  return score >= 70 ? 'critical' : score >= 40 ? 'elevated' : score >= 20 ? 'moderate' : 'low';
}

/** Conic-gradient risk ring (§8). Pure CSS, no chart lib. */
export function RiskRing({ value, size = 132 }: { value: number; size?: number }) {
  const color = `var(--${scoreBucket(value)})`;
  const inner = Math.round(size * 0.78);
  const style: CSSProperties = {
    width: size,
    height: size,
    background: `conic-gradient(${color} ${value * 3.6}deg, var(--muted) 0deg)`,
  };
  return (
    <div className="relative grid place-items-center rounded-full" style={style}>
      <div
        className="grid place-items-center rounded-full bg-card"
        style={{ width: inner, height: inner }}
      >
        <span className="text-3xl font-semibold tabular-nums">{value}</span>
        <span className="text-xs text-muted-foreground">/ 100 · {rating(value)}</span>
      </div>
    </div>
  );
}
