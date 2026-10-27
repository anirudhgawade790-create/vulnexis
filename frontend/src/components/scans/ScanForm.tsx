import axios from "axios";
import { useEffect } from "react";
import { useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Loader2 } from "lucide-react";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";

import type { ScanJobCreate, Target } from "@/types";

const schema = z.object({
  target_id: z.string().min(1, "Target is required"),
  scan_type: z.enum(["network", "windows", "full"]),
  options: z.string().default(""),
});

type FormValues = z.infer<typeof schema>;

interface ScanFormProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  targets: Target[];
  onSubmit: (data: ScanJobCreate) => Promise<unknown>;
  isPending: boolean;
}

/**
 * Form for launching a new scan. Validates target + scan type; the optional
 * `options` field accepts a JSON object string.
 */
export function ScanForm({ open, onOpenChange, targets, onSubmit, isPending }: ScanFormProps) {
  const {
    register,
    control,
    handleSubmit,
    reset,
    setError,
    formState: { errors },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { target_id: "", scan_type: "full", options: "" },
  });
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      reset();
      setSubmitError(null);
    }
  }, [open, reset]);

  const submit = async (values: FormValues) => {
    let options: Record<string, unknown> | undefined;
    const raw = values.options.trim();
    if (raw) {
      try {
        const parsed: unknown = JSON.parse(raw);
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          setError("options", { message: "Options must be a JSON object." });
          return;
        }
        options = Object.fromEntries(Object.entries(parsed));
      } catch (error) {
        if (error instanceof SyntaxError) {
          setError("options", { message: "Enter valid JSON." });
          return;
        }
        throw error;
      }
    }

    setSubmitError(null);
    try {
      await onSubmit({ target_id: values.target_id, scan_type: values.scan_type, options });
    } catch (error) {
      const requestTimedOut =
        axios.isAxiosError(error) &&
        (error.code === "ECONNABORTED" || error.code === "ETIMEDOUT");
      const detail = axios.isAxiosError<{ detail?: unknown }>(error)
        ? error.response?.data?.detail
        : undefined;
      setSubmitError(
        requestTimedOut
          ? "The request timed out. Check Scan History before retrying to avoid starting a duplicate scan."
          : typeof detail === "string"
          ? detail
          : error instanceof Error
            ? error.message
            : "Unable to start the scan. Please try again."
      );
      return;
    }
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Launch a scan</DialogTitle>
          <DialogDescription>
            Select a target and scan type. Windows scans require WinRM access.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit(submit)} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target_id">Target</Label>
            <Controller
              control={control}
              name="target_id"
              render={({ field }) => (
                <Select onValueChange={field.onChange} value={field.value}>
                  <SelectTrigger id="target_id" aria-invalid={Boolean(errors.target_id)}>
                    <SelectValue placeholder="Select a target…" />
                  </SelectTrigger>
                  <SelectContent>
                    {targets.map((t) => (
                      <SelectItem key={t.id} value={t.id}>
                        {t.name} — {t.scope_value}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            />
            {errors.target_id && (
              <p className="text-xs text-destructive">{errors.target_id.message}</p>
            )}
          </div>

          <div className="space-y-2">
            <Label htmlFor="scan_type">Scan type</Label>
            <Controller
              control={control}
              name="scan_type"
              render={({ field }) => (
                <Select onValueChange={field.onChange} value={field.value}>
                  <SelectTrigger id="scan_type">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="network">Network</SelectItem>
                    <SelectItem value="windows">Windows</SelectItem>
                    <SelectItem value="full">Full</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="options">Options (JSON, optional)</Label>
            <Textarea
              id="options"
              className="font-mono text-xs"
              placeholder={'{"ports": "1-1000", "timeout": 60}'}
              {...register("options")}
            />
            {errors.options && (
              <p className="text-xs text-destructive" role="alert">
                {errors.options.message}
              </p>
            )}
          </div>

          {submitError && (
            <p className="text-sm text-destructive" role="alert">
              {submitError}
            </p>
          )}

          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isPending}>
              {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Launch scan
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}