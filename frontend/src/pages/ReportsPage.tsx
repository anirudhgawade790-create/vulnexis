import { useState } from "react";
import { Download, FileText } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useListScans } from "@/hooks/useScans";
import { apiClient } from "@/api/client";
import { toast } from "@/components/ui/use-toast";

const REPORT_TYPES = [
  { id: "executive_summary", label: "Executive Summary", description: "High-level posture overview for management." },
  { id: "findings_detail", label: "Findings Detail", description: "Full list of all findings with evidence." },
  { id: "remediation_plan", label: "Remediation Plan", description: "Prioritized action plan with PowerShell scripts." },
  { id: "vulnerability_report", label: "Vulnerability Report", description: "CVE list with CVSS scores and KEV status." },
  { id: "baseline_compliance", label: "Baseline Compliance", description: "CIS/NIST compliance assessment results." },
];

export function ReportsPage() {
  const { data: scans = [] } = useListScans();
  const [selectedScanId, setSelectedScanId] = useState<string>("latest");
  const [downloading, setDownloading] = useState<string | null>(null);

  const completedScans = scans.filter((s) => s.status === "completed");

  const handleDownload = async (reportType: string, format: "pdf" | "csv") => {
    setDownloading(`${reportType}-${format}`);
    try {
      const scanId = selectedScanId === "latest" ? completedScans[0]?.id : selectedScanId;
      const res = await apiClient.get(`/reports/${reportType}`, {
        params: { scan_job_id: scanId, format },
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.download = `${reportType}_${new Date().toISOString().slice(0, 10)}.${format}`;
      link.click();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Please try again later.";
      toast({
        title: "Report download failed",
        description: message,
        variant: "destructive",
      });
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports"
        subtitle="Export scan results and compliance summaries."
      />

      {/* Scan selector */}
      <div className="flex items-center gap-3">
        <span className="text-sm font-medium">Scan:</span>
        <Select value={selectedScanId} onValueChange={setSelectedScanId}>
          <SelectTrigger className="w-64">
            <SelectValue placeholder="Select scan" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="latest">Latest completed scan</SelectItem>
            {completedScans.map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {s.id.slice(0, 8)}… · {s.scan_type} · {s.completed_at ? new Date(s.completed_at).toLocaleDateString() : ""}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Report cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {REPORT_TYPES.map((rt) => (
          <Card key={rt.id}>
            <CardHeader className="pb-2">
              <div className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-primary" />
                <span className="text-sm font-medium">{rt.label}</span>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">{rt.description}</p>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="flex-1 gap-1.5"
                  disabled={!!downloading}
                  onClick={() => handleDownload(rt.id, "pdf")}
                >
                  <Download className="h-3.5 w-3.5" />
                  {downloading === `${rt.id}-pdf` ? "…" : "PDF"}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="flex-1 gap-1.5"
                  disabled={!!downloading}
                  onClick={() => handleDownload(rt.id, "csv")}
                >
                  <Download className="h-3.5 w-3.5" />
                  {downloading === `${rt.id}-csv` ? "…" : "CSV"}
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
