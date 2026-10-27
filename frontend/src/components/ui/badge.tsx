import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        destructive:
          "border-transparent bg-destructive text-destructive-foreground",
        outline: "text-foreground",
        critical: "border-red-200 bg-red-100 text-red-800 dark:border-red-500/25 dark:bg-red-500/10 dark:text-red-300",
        high: "border-orange-200 bg-orange-100 text-orange-800 dark:border-orange-500/25 dark:bg-orange-500/10 dark:text-orange-300",
        medium: "border-yellow-200 bg-yellow-100 text-yellow-800 dark:border-amber-500/25 dark:bg-amber-500/10 dark:text-amber-300",
        low: "border-green-200 bg-green-100 text-green-800 dark:border-emerald-500/25 dark:bg-emerald-500/10 dark:text-emerald-300",
        info: "border-blue-200 bg-blue-100 text-blue-800 dark:border-cyan-500/25 dark:bg-cyan-500/10 dark:text-cyan-300",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
