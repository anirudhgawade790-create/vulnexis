import { useEffect, useRef, useState } from "react";

import { getScanProgressUrl } from "@/api/scans";
import type { ScanProgressEvent } from "@/types";

interface ProgressState {
  progress: number;
  phase: string;
  currentHost: string | null;
  message: string;
  done: boolean;
  error: string | null;
  events: ScanProgressEvent[];
}

const INITIAL: ProgressState = {
  progress: 0,
  phase: "idle",
  currentHost: null,
  message: "",
  done: false,
  error: null,
  events: [],
};

/**
 * Subscribes to the SSE progress stream for a scan job, parses events, and
 * cleans up on unmount or when the scan job id changes.
 */
export function useScanProgress(scanJobId: string | null | undefined) {
  const [state, setState] = useState<ProgressState>(INITIAL);
  const sourceRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!scanJobId) {
      setState(INITIAL);
      return;
    }

    const url = getScanProgressUrl(scanJobId);
    const source = new EventSource(url);
    sourceRef.current = source;

    source.onmessage = (ev: MessageEvent<string>) => {
      try {
        const data = JSON.parse(ev.data) as ScanProgressEvent;
        const isDone =
          data.progress >= 100 ||
          data.phase === "completed" ||
          data.phase === "failed";
        setState((prev) => ({
          progress: data.progress,
          phase: data.phase,
          currentHost: data.current_host,
          message: data.message,
          done: isDone,
          error: data.phase === "failed" ? data.message : null,
          events: [...prev.events, data].slice(-200),
        }));
        if (isDone) source.close();
      } catch {
        // Ignore malformed chunks.
      }
    };

    source.onerror = () => {
      setState((prev) => ({
        ...prev,
        error: prev.error ?? "Connection to scan progress stream lost.",
      }));
      source.close();
    };

    return () => {
      source.close();
      sourceRef.current = null;
    };
  }, [scanJobId]);

  return state;
}
