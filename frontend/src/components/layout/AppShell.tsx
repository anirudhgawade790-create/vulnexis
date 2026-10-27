import { useEffect, useState } from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import axios from "axios";

import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { Toaster } from "@/components/ui/toast";
import { useAuthStore } from "@/store/authStore";
import { getMe } from "@/api/auth";
import { Button } from "@/components/ui/button";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { tokenStorage } from "@/api/client";

export function AppShell() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const setUser = useAuthStore((state) => state.setUser);
  const logout = useAuthStore((state) => state.logout);
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const identity = useQuery({
    queryKey: ["auth", "me"],
    queryFn: getMe,
    enabled: isAuthenticated,
    retry: false,
    staleTime: 30_000,
    refetchOnWindowFocus: true,
  });

  useEffect(() => {
    if (identity.data) setUser(identity.data);
  }, [identity.data, setUser]);

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  if (identity.isLoading) return <LoadingSpinner label="Verifying your session…" />;
  if (identity.isError) {
    const isUnauthorized = axios.isAxiosError(identity.error) && identity.error.response?.status === 401;
    if (isUnauthorized) {
      tokenStorage.clear();
      logout();
      return <Navigate to="/login" state={{ from: location }} replace />;
    }
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-background p-6 text-center">
        <p className="text-sm text-muted-foreground">Your account could not be verified. Protected pages remain unavailable.</p>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => void identity.refetch()}>Retry</Button>
          <Button variant="ghost" onClick={() => { tokenStorage.clear(); logout(); }}>Sign out</Button>
        </div>
      </div>
    );
  }

  function toggleNavigation() {
    if (window.matchMedia("(min-width: 768px)").matches) {
      setCollapsed((current) => !current);
    } else {
      setMobileOpen((current) => !current);
    }
  }

  return (
    <div className="flex h-[100dvh] w-full overflow-hidden bg-background">
      <Sidebar
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        onClose={() => setMobileOpen(false)}
      />
      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <TopBar onMenuClick={toggleNavigation} />
        <main className="flex-1 overflow-y-auto px-4 py-6 sm:px-6 lg:px-8 lg:py-7">
          <div className="mx-auto w-full max-w-[1600px]">
            <Outlet />
          </div>
        </main>
      </div>
      <Toaster />
    </div>
  );
}
