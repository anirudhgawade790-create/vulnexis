import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";

import { AppShell } from "@/components/layout/AppShell";
import { LoadingSpinner } from "@/components/common/LoadingSpinner";
import { ProtectedRoute } from "@/components/common/ProtectedRoute";

const LoginPage = lazy(() => import("@/pages/LoginPage").then((m) => ({ default: m.LoginPage })));
const DashboardPage = lazy(() =>
  import("@/pages/DashboardPage").then((m) => ({ default: m.DashboardPage }))
);
const ScansPage = lazy(() => import("@/pages/ScansPage").then((m) => ({ default: m.ScansPage })));
const ScanDetailPage = lazy(() =>
  import("@/pages/ScanDetailPage").then((m) => ({ default: m.ScanDetailPage }))
);
const AssetsPage = lazy(() => import("@/pages/AssetsPage").then((m) => ({ default: m.AssetsPage })));
const AssetDetailPage = lazy(() =>
  import("@/pages/AssetDetailPage").then((m) => ({ default: m.AssetDetailPage }))
);
const VulnerabilitiesPage = lazy(() =>
  import("@/pages/VulnerabilitiesPage").then((m) => ({ default: m.VulnerabilitiesPage }))
);
const FindingsPage = lazy(() => import("@/pages/FindingsPage").then((m) => ({ default: m.FindingsPage })));
const RemediationPage = lazy(() =>
  import("@/pages/RemediationPage").then((m) => ({ default: m.RemediationPage }))
);
const BaselinePage = lazy(() => import("@/pages/BaselinePage").then((m) => ({ default: m.BaselinePage })));
const ChangeDetectionPage = lazy(() =>
  import("@/pages/ChangeDetectionPage").then((m) => ({ default: m.ChangeDetectionPage }))
);
const ReportsPage = lazy(() => import("@/pages/ReportsPage").then((m) => ({ default: m.ReportsPage })));
const SettingsPage = lazy(() => import("@/pages/SettingsPage").then((m) => ({ default: m.SettingsPage })));

function RouteLoadingFallback() {
  return (
    <div className="flex min-h-[50vh] items-center justify-center">
      <LoadingSpinner label="Loading application…" />
    </div>
  );
}

/**
 * Top-level router. AppShell handles auth guard internally and renders
 * child routes via <Outlet />.
 */
export function App() {
  return (
    <Suspense fallback={<RouteLoadingFallback />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        {/* All authenticated routes nested under AppShell */}
        <Route element={<AppShell />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/scans" element={<ProtectedRoute roles={["admin", "analyst"]}><ScansPage /></ProtectedRoute>} />
          <Route path="/scan-history" element={<ScansPage />} />
          <Route path="/scans/:id" element={<ScanDetailPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/network-discovery" element={<AssetsPage />} />
          <Route path="/assets/:id" element={<AssetDetailPage />} />
          <Route path="/vulnerabilities" element={<ProtectedRoute roles={["admin", "analyst"]}><VulnerabilitiesPage /></ProtectedRoute>} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/remediation" element={<ProtectedRoute roles={["admin", "analyst"]}><RemediationPage /></ProtectedRoute>} />
          <Route path="/baseline" element={<ProtectedRoute roles={["admin", "analyst"]}><BaselinePage /></ProtectedRoute>} />
          <Route path="/changes" element={<ProtectedRoute roles={["admin", "analyst"]}><ChangeDetectionPage /></ProtectedRoute>} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<ProtectedRoute roles={["admin"]}><SettingsPage /></ProtectedRoute>} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
