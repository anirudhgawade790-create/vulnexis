import { Navigate } from "react-router-dom";

import { useAuthStore } from "@/store/authStore";
import type { UserRole } from "@/types";
import { PageHeader } from "@/components/layout/PageHeader";

interface ProtectedRouteProps {
  roles?: UserRole[];
  children: React.ReactNode;
}

export function ProtectedRoute({ roles, children }: ProtectedRouteProps) {
  const user = useAuthStore((s) => s.user);
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  if (roles && user && !roles.includes(user.role)) {
    return (
      <div className="mx-auto max-w-2xl py-10">
        <PageHeader title="403 · Access denied" subtitle="Your account does not have permission to access this page." />
      </div>
    );
  }
  return <>{children}</>;
}
