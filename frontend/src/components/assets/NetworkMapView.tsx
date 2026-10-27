import { ScatterChart, Scatter, XAxis, YAxis, ZAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import type { Asset } from "@/types";

interface NetworkMapViewProps {
  assets: Asset[];
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#94a3b8",
};

function riskToSeverity(score: number | null): string {
  if (!score) return "info";
  if (score >= 8) return "critical";
  if (score >= 6) return "high";
  if (score >= 4) return "medium";
  if (score >= 2) return "low";
  return "info";
}

const CustomDot = (props: Record<string, unknown>) => {
  const { cx, cy, payload } = props as { cx: number; cy: number; payload: { severity: string; fill: string } };
  return <circle cx={cx} cy={cy} r={6} fill={SEVERITY_COLOR[payload.severity] ?? "#94a3b8"} fillOpacity={0.8} stroke="#fff" strokeWidth={1} />;
};

export function NetworkMapView({ assets }: NetworkMapViewProps) {
  const data = assets.map((a, i) => ({
    x: i,
    y: a.risk_score ?? 0,
    z: (a.open_ports?.length ?? 0) + 1,
    severity: riskToSeverity(a.risk_score),
    ip: a.ip_address,
    hostname: a.hostname ?? a.ip_address,
  }));

  return (
    <Card id="network-discovery" className="scroll-mt-24">
      <CardHeader className="pb-2">
        <p className="text-sm font-semibold">Network Risk Map</p>
        <p className="mt-1 text-xs text-muted-foreground">Asset risk and open-port count · no network relationships inferred</p>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={260}>
          <ScatterChart margin={{ top: 4, right: 16, left: 0, bottom: 4 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
            <XAxis dataKey="x" type="number" name="Asset" tick={false} label={{ value: "Assets", position: "insideBottom", offset: -4, fontSize: 11 }} />
            <YAxis dataKey="y" type="number" name="Risk Score" domain={[0, 10]} tick={{ fontSize: 11 }} label={{ value: "Risk", angle: -90, position: "insideLeft", fontSize: 11 }} />
            <ZAxis dataKey="z" range={[40, 200]} name="Ports" />
            <Tooltip
              cursor={{ strokeDasharray: "3 3" }}
              content={({ payload }) => {
                if (!payload?.length) return null;
                const d = payload[0].payload as { ip: string; hostname: string; y: number; z: number; severity: string };
                return (
                  <div className="rounded border bg-background p-2 text-xs shadow">
                    <p className="font-semibold">{d.hostname}</p>
                    <p className="text-muted-foreground">{d.ip}</p>
                    <p>Risk: {d.y.toFixed(1)} · Ports: {d.z - 1}</p>
                    <p className="capitalize" style={{ color: SEVERITY_COLOR[d.severity] }}>{d.severity}</p>
                  </div>
                );
              }}
            />
            <Scatter data={data} shape={<CustomDot />} />
          </ScatterChart>
        </ResponsiveContainer>
        <div className="flex flex-wrap gap-3 mt-2">
          {Object.entries(SEVERITY_COLOR).map(([sev, color]) => (
            <div key={sev} className="flex items-center gap-1 text-xs text-muted-foreground capitalize">
              <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: color }} />
              {sev}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
