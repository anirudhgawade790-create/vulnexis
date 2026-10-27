import { useState, type FormEvent } from "react";
import axios from "axios";
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
import { toast } from "@/components/ui/use-toast";
import { useCreateTarget } from "@/hooks/useTargets";
import type { BusinessCriticality, ScopeType, TargetCreate } from "@/types";

interface TargetCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function TargetCreateDialog({ open, onOpenChange }: TargetCreateDialogProps) {
  const createTarget = useCreateTarget();
  const [name, setName] = useState("");
  const [scopeValue, setScopeValue] = useState("");
  const [scopeType, setScopeType] = useState<ScopeType>("cidr");
  const [criticality, setCriticality] = useState<BusinessCriticality>("medium");
  const [error, setError] = useState<string | null>(null);

  function close() {
    setError(null);
    setName("");
    setScopeValue("");
    setScopeType("cidr");
    setCriticality("medium");
    onOpenChange(false);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (!name.trim() || !scopeValue.trim()) {
      setError("Enter both a target name and an authorized scope.");
      return;
    }

    const data: TargetCreate = {
      name: name.trim(),
      scope_type: scopeType,
      scope_value: scopeValue.trim(),
      business_criticality: criticality,
      is_active: true,
    };

    try {
      await createTarget.mutateAsync(data);
      toast({
        title: "Scan target added",
        description: "Run a scan to discover assets in this scope.",
        variant: "default",
      });
      close();
    } catch (requestError) {
      const detail = axios.isAxiosError<{ detail?: unknown }>(requestError)
        ? requestError.response?.data?.detail
        : undefined;
      setError(
        typeof detail === "string"
          ? detail
          : requestError instanceof Error
            ? requestError.message
            : "Unable to add this target. Please try again."
      );
    }
  }

  return (
    <Dialog open={open} onOpenChange={(nextOpen) => (nextOpen ? onOpenChange(true) : close())}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add an asset discovery target</DialogTitle>
          <DialogDescription>
            Register an authorized host or network scope. Assets appear in inventory after a scan.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="target-name">Target name</Label>
            <Input
              id="target-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Production network"
              required
              maxLength={255}
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
            <div className="space-y-2">
              <Label>Scope type</Label>
              <Select value={scopeType} onValueChange={(value) => setScopeType(value as ScopeType)}>
                <SelectTrigger aria-label="Scope type"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="ip">IP address</SelectItem>
                  <SelectItem value="cidr">CIDR network</SelectItem>
                  <SelectItem value="hostname">Hostname</SelectItem>
                  <SelectItem value="range">IP range</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="target-scope">Scope value</Label>
              <Input
                id="target-scope"
                value={scopeValue}
                onChange={(event) => setScopeValue(event.target.value)}
                placeholder={scopeType === "cidr" ? "10.0.0.0/24" : "10.0.0.10"}
                required
              />
            </div>
          </div>
          <div className="space-y-2">
            <Label>Business criticality</Label>
            <Select
              value={criticality}
              onValueChange={(value) => setCriticality(value as BusinessCriticality)}
            >
              <SelectTrigger aria-label="Business criticality"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {error && <p className="text-sm text-destructive" role="alert">{error}</p>}
          <DialogFooter>
            <Button type="button" variant="ghost" onClick={close} disabled={createTarget.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={createTarget.isPending}>
              {createTarget.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Add target
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
