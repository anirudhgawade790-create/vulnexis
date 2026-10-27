import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { AssetDetailPanel } from "@/components/assets/AssetDetailPanel";
import { FindingDetailPanel } from "@/components/findings/FindingDetailPanel";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { Button } from "@/components/ui/button";
import { useAsset, useAssetFindings, useAssetHistory } from "@/hooks/useAssets";
import type { Finding } from "@/types";

export function AssetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const { data: asset, isLoading } = useAsset(id);
  const { data: findings = [], isLoading: findingsLoading } = useAssetFindings(id);
  const { data: history = [] } = useAssetHistory(id);

  if (isLoading) return <LoadingSpinner label="Loading asset…" />;
  if (!asset) return <p className="text-sm text-muted-foreground">Asset not found.</p>;

  return (
    <div className="space-y-6">
      <PageHeader
        title={asset.hostname ?? asset.ip_address}
        subtitle={`${asset.ip_address} · ${asset.asset_type} · Risk: ${asset.risk_score?.toFixed(1) ?? "—"}`}
        action={
          <Link to="/assets">
            <Button variant="outline" size="sm" className="gap-1.5">
              <ArrowLeft className="h-4 w-4" /> Back
            </Button>
          </Link>
        }
      />

      <AssetDetailPanel
        asset={asset}
        findings={findings}
        history={history}
        findingsLoading={findingsLoading}
        onFindingSelect={setSelectedFinding}
      />

      <FindingDetailPanel
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
