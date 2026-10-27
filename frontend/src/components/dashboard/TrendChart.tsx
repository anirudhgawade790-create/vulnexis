import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SEVERITY_LABELS } from "@/lib/constants";
import type { TrendDataPoint } from "@/types";

const COLORS: Record<string, string> = {
  critical: "#F87171",
  high: "#FB923C",
  medium: "#FBBF24",
  low: "#34D399",
};

interface TrendChartProps {
  data: TrendDataPoint[];
  periodDays?: number;
  isError?: boolean;
}

/**
 * Stacked-area trend chart showing how finding severity evolved over time.
 * Empty state renders a friendly placeholder instead of a broken chart.
 */
export function TrendChart({ data, periodDays, isError = false }: TrendChartProps) {
  const hasData = data.some((d) => d.total > 0);

  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-end justify-between gap-2">
          <span>
            <span className="eyebrow block">Historical assessment data</span>
            <span className="mt-1 block">Security trend</span>
          </span>
          {periodDays ? (
            <span className="text-xs font-normal text-muted-foreground">
              Last {periodDays} days
            </span>
          ) : null}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-72">
          {isError ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 text-sm text-destructive">
              <span>Historical trend could not be loaded.</span>
            </div>
          ) : hasData ? (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={data}
                margin={{ top: 8, right: 12, left: 0, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
                <XAxis
                  dataKey="date"
                  tickLine={false}
                  axisLine={false}
                  tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
                />
                <YAxis
                  tickLine={false}
                  axisLine={false}
                  tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
                />
                <Tooltip
                  contentStyle={{
                    background: "hsl(var(--card))",
                    border: "1px solid hsl(var(--border))",
                    borderRadius: "10px",
                  }}
                  labelStyle={{ color: "hsl(var(--foreground))" }}
                />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stackId="1"
                  fill={COLORS.critical}
                  fillOpacity={0.12}
                  stroke={COLORS.critical}
                  strokeWidth={2}
                  name={SEVERITY_LABELS.critical}
                />
                <Area
                  type="monotone"
                  dataKey="high"
                  stackId="1"
                  fill={COLORS.high}
                  fillOpacity={0.12}
                  stroke={COLORS.high}
                  strokeWidth={2}
                  name={SEVERITY_LABELS.high}
                />
                <Area
                  type="monotone"
                  dataKey="medium"
                  stackId="1"
                  fill={COLORS.medium}
                  fillOpacity={0.12}
                  stroke={COLORS.medium}
                  strokeWidth={2}
                  name={SEVERITY_LABELS.medium}
                />
                <Area
                  type="monotone"
                  dataKey="low"
                  stackId="1"
                  fill={COLORS.low}
                  fillOpacity={0.12}
                  stroke={COLORS.low}
                  strokeWidth={2}
                  name={SEVERITY_LABELS.low}
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
              No trend data available yet. Run scans to populate.
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}