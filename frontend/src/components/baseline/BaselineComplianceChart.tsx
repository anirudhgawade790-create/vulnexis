import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import type { BaselineControl } from "@/types";

interface BaselineComplianceChartProps {
  controls: BaselineControl[];
}

export function BaselineComplianceChart({ controls }: BaselineComplianceChartProps) {
  // Group by category
  const categoryMap: Record<string, { pass: number; fail: number; unknown: number }> = {};

  for (const c of controls) {
    const cat = c.category ?? "General";
    if (!categoryMap[cat]) categoryMap[cat] = { pass: 0, fail: 0, unknown: 0 };
    categoryMap[cat][c.result]++;
  }

  const data = Object.entries(categoryMap).map(([name, counts]) => ({
    name,
    Pass: counts.pass,
    Fail: counts.fail,
    Unknown: counts.unknown,
  }));

  if (!data.length) return null;

  return (
    <Card>
      <CardHeader className="pb-2 text-sm font-medium">Compliance by Category</CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={data} margin={{ top: 4, right: 16, left: 0, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
            <XAxis dataKey="name" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 11 }} />
            <Tooltip
              contentStyle={{ fontSize: 12, borderRadius: 8 }}
            />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Bar dataKey="Pass" stackId="a" fill="#22c55e" />
            <Bar dataKey="Fail" stackId="a" fill="#ef4444" />
            <Bar dataKey="Unknown" stackId="a" fill="#a3a3a3" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
}
