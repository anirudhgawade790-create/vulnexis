import { Wifi, WifiOff } from "lucide-react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { useScanProgress } from "@/hooks/useScanProgress";
import { cn } from "@/lib/utils";

interface ScanProgressDrawerProps {
  scanJobId: string | null;
  onClose: () => void;
}

export function ScanProgressDrawer({ scanJobId, onClose }: ScanProgressDrawerProps) {
  const progress = useScanProgress(scanJobId);

  return (
    <Dialog open={!!scanJobId} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Scan Progress</DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          {/* Progress bar */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-sm">
              <span className="font-medium capitalize">{progress.phase.replace(/_/g, " ")}</span>
              <span className="text-muted-foreground">{progress.progress}%</span>
            </div>
            <Progress value={progress.progress} className="h-2" />
          </div>

          {/* Current host */}
          {progress.currentHost && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Wifi className="h-4 w-4 text-primary" />
              Scanning: <span className="font-mono">{progress.currentHost}</span>
            </div>
          )}

          {/* Status message */}
          {progress.message && (
            <p className="text-sm text-muted-foreground">{progress.message}</p>
          )}

          {/* Error */}
          {progress.error && (
            <div className="flex items-center gap-2 rounded-lg border border-red-500/25 bg-red-500/10 px-3 py-2 text-sm text-red-300">
              <WifiOff className="h-4 w-4 shrink-0" />
              {progress.error}
            </div>
          )}

          {/* Done */}
          {progress.done && !progress.error && (
            <div className="rounded-lg border border-emerald-500/25 bg-emerald-500/10 px-3 py-2 text-sm font-medium text-emerald-300">
              Scan completed successfully.
            </div>
          )}

          {/* Per-host event log */}
          {progress.events.length > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground mb-1.5">Event Log</p>
              <div className="h-40 space-y-0.5 overflow-y-auto rounded-lg border border-border bg-background p-3">
                {progress.events.slice(-50).map((ev, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs font-mono">
                    <span className={cn("shrink-0", ev.phase === "failed" ? "text-red-400" : "text-green-400")}>
                      [{ev.progress}%]
                    </span>
                    {ev.current_host && (
                      <span className="text-blue-400 shrink-0">{ev.current_host}</span>
                    )}
                    <span className="text-gray-300 break-words">{ev.message}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
