import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';
import type { Severity } from '@/lib/types';

const badgeVariants = cva(
  'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        secondary: 'border-transparent bg-secondary text-secondary-foreground',
        outline: 'text-foreground',
        critical: 'border-transparent bg-critical text-critical-foreground',
        warn: 'border-transparent bg-warn text-warn-foreground',
        clear: 'border-transparent bg-clear text-clear-foreground',
      },
    },
    defaultVariants: { variant: 'default' },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

/** Map a finding severity to a risk-palette badge. */
const SEV_VARIANT: Record<Severity, BadgeProps['variant']> = {
  critical: 'critical',
  high: 'critical',
  medium: 'warn',
  low: 'clear',
  info: 'secondary',
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge variant={SEV_VARIANT[severity]} className="uppercase tracking-wide">
      {severity}
    </Badge>
  );
}

export { Badge, SeverityBadge, badgeVariants };
