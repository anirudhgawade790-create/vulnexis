import { RadialBar, RadialBarChart, PolarAngleAxis, ResponsiveContainer } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

function gaugeColor(score: number): string {
  if (score >= 75) return "#34D399";
  if (score >= 50) return "#22D3EE";
  if (score >= 25) return "#FBBF24";
  return "#F87171";
}

interface RiskGaugeProps {
  score: number;
  unavailable?: boolean;
}

export function RiskGauge({ score, unavailable = false }: RiskGaugeProps) {
  const data = [{ name: "posture", value: unavailable ? 0 : Math.round(score), fill: gaugeColor(score) }];
  const label =
    score >= 75 ? "Strong" : score >= 50 ? "Watch" : score >= 25 ? "At risk" : "Needs attention";

  return (
    <Card className="overflow-hidden">
      <CardHeader className="pb-0">
        <p className="eyebrow">Internal posture metric</p>
        <CardTitle className="pt-1">Security Posture</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative h-40">
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart
              innerRadius="78%"
              outerRadius="100%"
              data={data}
              startAngle={90}
              endAngle={-270}
            >
              <PolarAngleAxis type="number" domain={[0, 100]} angleAxisId={0} tick={false} />
              <RadialBar background dataKey="value" cornerRadius={10} />
            </RadialBarChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-3xl font-semibold tabular-nums">{unavailable ? "—" : Math.round(score)}</span>
            <span className="mt-1 text-[11px] font-medium text-muted-foreground">{unavailable ? "Unavailable" : label}</span>
          </div>
        </div>
        <p className="mt-1 text-center text-[11px] leading-4 text-muted-foreground">
          Higher is better. This platform score is not a CVSS rating.
        </p>
      </CardContent>
    </Card>
  );
}
