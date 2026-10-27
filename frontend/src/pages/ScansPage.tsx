import { useState } from "react";
import { useLocation } from "react-router-dom";
import { Plus } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Button } from "@/components/ui/button";
import { ScanJobTable } from "@/components/scans/ScanJobTable";
import { ScanForm } from "@/components/scans/ScanForm";
import { ScanProgressDrawer } from "@/components/scans/ScanProgressDrawer";
import { useListScans, useCancelScan, useCreateScan } from "@/hooks/useScans";
import { useListTargets } from "@/hooks/useTargets";
import type { ScanJobCreate } from "@/types";
import { useAuthStore } from "@/store/authStore";

export function ScansPage() {
  const role = useAuthStore((state) => state.user?.role);
  const location = useLocation();
  const isHistory = location.pathname === "/scan-history";
  const canManageScans = role === "admin" || role === "analyst";
  const [showForm, setShowForm] = useState(false);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);

  const { data: scans = [], isLoading } = useListScans();
  const { data: targets = [] } = useListTargets();
  const cancelScan = useCancelScan();
  const createScan = useCreateScan();

  const handleSubmit = async (data: ScanJobCreate) => {
    const scan = await createScan.mutateAsync(data);
    setActiveScanId(scan.id);
    setShowForm(false);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={isHistory ? "Scan History" : "Vulnerability Scanner"}
        subtitle={
          isHistory
            ? "Review completed, active, and previous security assessments."
            : "Configure, launch, and monitor vulnerability scans."
        }
        action={
          canManageScans && !isHistory ? (
            <Button onClick={() => setShowForm(true)} className="gap-2">
              <Plus className="h-4 w-4" /> New Scan
            </Button>
          ) : undefined
        }
      />

      <ScanJobTable
        scans={scans}
        isLoading={isLoading}
        onCancel={canManageScans ? (id) => cancelScan.mutate(id) : undefined}
      />

      {/* ScanForm uses its own Dialog internally */}
      {canManageScans && (
        <ScanForm
          open={showForm}
          onOpenChange={setShowForm}
          targets={targets}
          onSubmit={handleSubmit}
          isPending={createScan.isPending}
        />
      )}

      {/* Live progress */}
      {canManageScans && (
        <ScanProgressDrawer
          scanJobId={activeScanId}
          onClose={() => setActiveScanId(null)}
        />
      )}
    </div>
  );
}
