import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { ScanProgressDrawer } from "@/components/scans/ScanProgressDrawer";
import { ScanResultsSummary } from "@/components/scans/ScanResultsSummary";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { Button } from "@/components/ui/button";
import { useScan, useScanResults } from "@/hooks/useScans";
import { SCAN_STATUS_LABELS } from "@/lib/constants";

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: scan, isLoading } = useScan(id);
  const { data: results } = useScanResults(id);
  const [showProgress, setShowProgress] = useState(false);

  if (isLoading) return <LoadingSpinner label="Loading scan…" />;
  if (!scan) return <p className="text-sm text-muted-foreground">Scan not found.</p>;

  const isActive = scan.status === "running" || scan.status === "queued";

  return (
    <div className="space-y-6">
      <PageHeader
        title={`Scan ${scan.id.slice(0, 8)}…`}
        subtitle={`${scan.scan_type} scan · ${SCAN_STATUS_LABELS[scan.status]}`}
        action={
          <div className="flex items-center gap-2">
            <Link to="/scans">
              <Button variant="outline" size="sm" className="gap-1.5">
                <ArrowLeft className="h-4 w-4" /> Back
              </Button>
            </Link>
            {isActive && (
              <Button size="sm" onClick={() => setShowProgress(true)}>
                View Live Progress
              </Button>
            )}
          </div>
        }
      />

      {results && <ScanResultsSummary summary={results} />}

      {!results && !isActive && (
        <p className="text-sm text-muted-foreground">No results available yet.</p>
      )}

      <div className="flex gap-4 flex-wrap">
        <Link to={`/assets?scan_job_id=${scan.id}`}>
          <Button variant="outline" size="sm">View Assets from this Scan</Button>
        </Link>
        <Link to={`/findings?scan_job_id=${scan.id}`}>
          <Button variant="outline" size="sm">View Findings from this Scan</Button>
        </Link>
      </div>

      {(isActive || showProgress) && (
        <ScanProgressDrawer
          scanJobId={id ?? null}
          onClose={() => setShowProgress(false)}
        />
      )}
    </div>
  );
}
