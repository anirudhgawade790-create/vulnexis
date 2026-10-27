import * as React from "react";

import { cn } from "@/lib/utils";

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
  className?: string;
}

export function PageHeader({ title, subtitle, action, className }: PageHeaderProps) {
  return (
    <div className={cn("flex flex-wrap items-start justify-between gap-4 border-b border-border/70 pb-5", className)}>
      <div className="max-w-3xl space-y-1.5">
        <h1 className="text-[26px] font-semibold tracking-tight sm:text-[30px]">{title}</h1>
        {subtitle && (
          <p className="text-sm leading-6 text-muted-foreground">{subtitle}</p>
        )}
      </div>
      {action && <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">{action}</div>}
    </div>
  );
}
