import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SEVERITY_LABELS } from "@/lib/constants";
import type { Severity } from "@/types";

interface SeverityDonutProps {
  counts: Record<string, number>;
}

const COLORS: Record<Severity, string> = {
  critical: "#F87171",
  high: "#FB923C",
  medium: "#FBBF24",
  low: "#34D399",
  info: "#22D3EE",
};

export function SeverityDonut({ counts }: SeverityDonutProps) {
  const keys: Severity[] = ["critical", "high", "medium", "low", "info"];
  const data = keys
    .filter((k) => (counts[k] ?? 0) > 0)
    .map((k) => ({ name: k, value: counts[k] ?? 0, color: COLORS[k] }));

  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <Card className="min-w-0">
      <CardHeader>
        <p className="eyebrow">Current scan inventory</p>
        <CardTitle className="pt-1">Findings by severity</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative h-48">
          {data.length === 0 ? (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
              No findings
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={2}
                  stroke="hsl(var(--card))"
                >
                  {data.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value: number, name: string) => [
                    `${value}`,
                    SEVERITY_LABELS[name as Severity] ?? name,
                  ]}
                  contentStyle={{
                    background: "hsl(var(--popover))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "10px",
                    color: "hsl(var(--foreground))",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
          {total > 0 && (
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold">{total}</span>
              <span className="text-xs text-muted-foreground">open</span>
            </div>
          )}
        </div>
        <div className="mt-3 grid grid-cols-2 gap-x-3 gap-y-2 text-[11px] sm:grid-cols-3 xl:grid-cols-2">
          {keys.map((k) => (
            <span key={k} className="flex items-center gap-1.5">
              <span
                className="inline-block h-2.5 w-2.5 rounded-full"
                style={{ background: COLORS[k] }}
              />
              {SEVERITY_LABELS[k]} ({counts[k] ?? 0})
            </span>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
