import { useState } from "react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { EmptyState } from "@/components/common/EmptyState";
import { SeverityBadge } from "@/components/common/SeverityBadge";
import { Settings, Trash2, UserCheck } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { listUsers, deleteUser } from "@/api/users";
import { useListTargets, useDeleteTarget } from "@/hooks/useTargets";
import { useListPolicies } from "@/hooks/useBaseline";
import { useAuthStore } from "@/store/authStore";

export function SettingsPage() {
  const currentUser = useAuthStore((s) => s.user);
  const isAdmin = currentUser?.role === "admin";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        subtitle="Manage users, targets, and baseline policies."
      />

      <Tabs defaultValue="users">
        <TabsList>
          <TabsTrigger value="users">Users</TabsTrigger>
          <TabsTrigger value="targets">Targets</TabsTrigger>
          <TabsTrigger value="policies">Baseline Policies</TabsTrigger>
        </TabsList>

        <TabsContent value="users" className="mt-4">
          <UsersTab isAdmin={isAdmin} />
        </TabsContent>

        <TabsContent value="targets" className="mt-4">
          <TargetsTab isAdmin={isAdmin} />
        </TabsContent>

        <TabsContent value="policies" className="mt-4">
          <PoliciesTab isAdmin={isAdmin} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function UsersTab({ isAdmin }: { isAdmin: boolean }) {
  const qc = useQueryClient();
  const { data: users = [], isLoading } = useQuery({ queryKey: ["users"], queryFn: listUsers });
  const del = useMutation({ mutationFn: deleteUser, onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }) });

  if (isLoading) return <LoadingSpinner label="Loading users…" />;

  return (
    <Card>
      <CardHeader className="pb-2 text-sm font-medium">Users ({users.length})</CardHeader>
      <CardContent className="p-0">
        <div className="divide-y">
          {users.map((u) => (
            <div key={u.id} className="flex items-center justify-between px-4 py-3">
              <div className="flex items-center gap-3">
                <UserCheck className="h-4 w-4 text-muted-foreground" />
                <div>
                  <p className="text-sm font-medium">{u.full_name ?? u.username}</p>
                  <p className="text-xs text-muted-foreground">{u.email} · {u.role}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {u.is_active ? (
                  <span className="text-xs text-green-600 font-medium">Active</span>
                ) : (
                  <span className="text-xs text-muted-foreground">Inactive</span>
                )}
                {isAdmin && (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0 text-red-500 hover:text-red-700"
                    onClick={() => { if (confirm(`Delete user ${u.username}?`)) del.mutate(u.id); }}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function TargetsTab({ isAdmin }: { isAdmin: boolean }) {
  const { data: targets = [], isLoading } = useListTargets();
  const del = useDeleteTarget();

  if (isLoading) return <LoadingSpinner label="Loading targets…" />;
  if (!targets.length) return <EmptyState icon={Settings} title="No targets" description="Create a target to start scanning." />;

  return (
    <Card>
      <CardHeader className="pb-2 text-sm font-medium">Targets ({targets.length})</CardHeader>
      <CardContent className="p-0">
        <div className="divide-y">
          {targets.map((t) => (
            <div key={t.id} className="flex items-center justify-between px-4 py-3">
              <div>
                <p className="text-sm font-medium">{t.name}</p>
                <p className="text-xs text-muted-foreground font-mono">{t.scope_value} · {t.scope_type}</p>
              </div>
              <div className="flex items-center gap-2">
                <SeverityBadge severity={t.business_criticality as never} />
                {isAdmin && (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 w-7 p-0 text-red-500 hover:text-red-700"
                    onClick={() => { if (confirm(`Delete target ${t.name}?`)) del.mutate(t.id); }}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function PoliciesTab({ isAdmin }: { isAdmin: boolean }) {
  const { data: policies = [], isLoading } = useListPolicies();

  if (isLoading) return <LoadingSpinner label="Loading policies…" />;
  if (!policies.length) return <EmptyState icon={Settings} title="No policies" description="Baseline policies will appear here." />;

  return (
    <Card>
      <CardHeader className="pb-2 text-sm font-medium">Baseline Policies ({policies.length})</CardHeader>
      <CardContent className="p-0">
        <div className="divide-y">
          {policies.map((p) => (
            <div key={p.id} className="flex items-center justify-between px-4 py-3">
              <div>
                <p className="text-sm font-medium">{p.name}</p>
                <p className="text-xs text-muted-foreground">{p.framework} v{p.version} · {p.controls.length} controls</p>
              </div>
              <span className={`text-xs font-medium ${p.is_active ? "text-green-600" : "text-muted-foreground"}`}>
                {p.is_active ? "Active" : "Inactive"}
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
