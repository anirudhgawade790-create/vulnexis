import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { FindingsList } from "@/components/findings/FindingsList";
import { AssetCard } from "./AssetCard";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import type { Asset, Finding } from "@/types";

interface AssetDetailPanelProps {
  asset: Asset;
  findings?: Finding[];
  history?: Asset[];
  findingsLoading?: boolean;
  onFindingSelect?: (f: Finding) => void;
}

export function AssetDetailPanel({ asset, findings = [], history = [], findingsLoading, onFindingSelect }: AssetDetailPanelProps) {
  const ports = asset.open_ports ?? [];
  const winDetails = asset.windows_details;

  return (
    <Tabs defaultValue="overview" className="w-full">
      <TabsList className="mb-4">
        <TabsTrigger value="overview">Overview</TabsTrigger>
        <TabsTrigger value="ports">Open Ports ({ports.length})</TabsTrigger>
        {asset.is_windows && <TabsTrigger value="windows">Windows Checks</TabsTrigger>}
        <TabsTrigger value="findings">Findings ({findings.length})</TabsTrigger>
        <TabsTrigger value="history">History ({history.length})</TabsTrigger>
      </TabsList>

      {/* Overview */}
      <TabsContent value="overview" className="space-y-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 text-sm">
          <InfoRow label="IP Address" value={asset.ip_address} mono />
          {asset.hostname && <InfoRow label="Hostname" value={asset.hostname} />}
          {asset.mac_address && <InfoRow label="MAC" value={asset.mac_address} mono />}
          {asset.os_name && <InfoRow label="OS" value={`${asset.os_name} ${asset.os_version ?? ""}`} />}
          {asset.os_arch && <InfoRow label="Arch" value={asset.os_arch} />}
          <InfoRow label="Type" value={asset.asset_type} />
          <InfoRow label="Criticality" value={asset.business_criticality} />
          {asset.risk_score !== null && (
            <InfoRow label="Risk Score" value={asset.risk_score.toFixed(1)} />
          )}
          <InfoRow label="Last Seen" value={new Date(asset.last_seen_at).toLocaleString()} />
        </div>
        {asset.is_supported_os === false && (
          <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 font-medium">
            ⚠ Unsupported OS — no longer receiving security updates
          </div>
        )}
      </TabsContent>

      {/* Open Ports */}
      <TabsContent value="ports">
        {!ports.length ? (
          <p className="text-sm text-muted-foreground">No open ports detected.</p>
        ) : (
          <div className="rounded-md border overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b bg-muted/40 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2 text-left">Port</th>
                  <th className="px-4 py-2 text-left">Protocol</th>
                  <th className="px-4 py-2 text-left">Service</th>
                  <th className="px-4 py-2 text-left">Version</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {ports.map((p, i) => (
                  <tr key={i} className="hover:bg-muted/20">
                    <td className="px-4 py-2 font-mono font-semibold">{p.port}</td>
                    <td className="px-4 py-2 uppercase text-xs">{p.protocol}</td>
                    <td className="px-4 py-2">{p.service}</td>
                    <td className="px-4 py-2 text-muted-foreground text-xs">{p.version ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </TabsContent>

      {/* Windows Checks */}
      {asset.is_windows && (
        <TabsContent value="windows">
          {!winDetails ? (
            <p className="text-sm text-muted-foreground">No Windows details available.</p>
          ) : (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 text-sm">
              {Object.entries(winDetails).map(([k, v]) => (
                <InfoRow key={k} label={k.replace(/_/g, " ")} value={String(v ?? "—")} />
              ))}
            </div>
          )}
        </TabsContent>
      )}

      {/* Findings */}
      <TabsContent value="findings">
        {findingsLoading ? (
          <LoadingSpinner label="Loading findings…" />
        ) : (
          <FindingsList findings={findings} onSelect={onFindingSelect} />
        )}
      </TabsContent>

      {/* History */}
      <TabsContent value="history">
        {!history.length ? (
          <p className="text-sm text-muted-foreground">No scan history for this asset.</p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {history.map((a) => <AssetCard key={a.id} asset={a} />)}
          </div>
        )}
      </TabsContent>
    </Tabs>
  );
}

function InfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded bg-muted/40 px-3 py-2">
      <p className="text-xs text-muted-foreground capitalize">{label}</p>
      <p className={mono ? "font-mono text-xs font-semibold" : "font-medium truncate"}>{value}</p>
    </div>
  );
}
