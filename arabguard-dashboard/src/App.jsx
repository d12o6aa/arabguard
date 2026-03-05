// ─── App.jsx ──────────────────────────────────────────────────────────────────
import { Routes, Route, useLocation } from "react-router-dom";
import { AnimatePresence } from "framer-motion";
import { Sidebar } from "./components/layout/Sidebar";
import { TopNavbar } from "./components/layout/TopNavbar";
import { useGuard } from "./hooks/useGuard";

import DashboardPage from "./pages/Dashboard";
import LogsPage      from "./pages/Logs";
import AnalyticsPage from "./pages/Analytics";
import QueuePage     from "./pages/Queue";
import DocsPage      from "./pages/Docs";
import SettingsPage  from "./pages/Settings";

export default function App() {
  const location = useLocation();

  // All values come from the real API — no mock data
  const {
    stats,
    refreshStats,
    health,
    queueCount,    // derived: threats with status === 'FLAGGED'
    threats,
    isMockMode,
  } = useGuard();

  // Safe guard: threats is always an array (initialised as [] in useGuard)
  const flaggedCount = queueCount;

  return (
    <div className="min-h-screen bg-[#090909] bg-grid text-zinc-100">
      {/* Ambient glow blobs */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute -top-60 -left-60 w-[500px] h-[500px] bg-emerald-500/4 rounded-full blur-3xl" />
        <div className="absolute top-1/2 -right-60 w-[400px] h-[400px] bg-blue-500/4 rounded-full blur-3xl" />
        <div className="absolute -bottom-60 left-1/3 w-[400px] h-[400px] bg-rose-500/4 rounded-full blur-3xl" />
      </div>

      {/* Scan line */}
      <div className="scan-line" />

      {/* Layout */}
      <Sidebar
        queueCount={flaggedCount}
        health={health}
      />

      <div className="ml-60 flex flex-col min-h-screen relative z-10">
        <TopNavbar
          stats={stats}
          isMockMode={isMockMode}
          onRefresh={refreshStats}
          flaggedCount={flaggedCount}
        />

        <main className="flex-1 pt-16 px-6 py-6">
          <AnimatePresence mode="wait">
            <Routes location={location} key={location.pathname}>
              <Route path="/"          element={<DashboardPage />} />
              <Route path="/logs"      element={<LogsPage />} />
              <Route path="/analytics" element={<AnalyticsPage />} />
              <Route path="/queue"     element={<QueuePage />} />
              <Route path="/docs"      element={<DocsPage />} />
              <Route path="/settings"  element={<SettingsPage />} />
            </Routes>
          </AnimatePresence>
        </main>

        {/* Footer */}
        <footer className="px-6 py-4 border-t border-zinc-800/30 flex items-center justify-between text-xs text-zinc-800 font-mono">
          <span>ArabGuard v1.0.0 · Apache 2.0</span>
          <span>
            <a
              href="https://huggingface.co/d12o6aa/ArabGuard"
              className="hover:text-zinc-600 transition-colors"
            >
              d12o6aa/ArabGuard
            </a>
            {" · "}MARBERT · F1=0.97 · P=0.96 · R=0.98
          </span>
        </footer>
      </div>
    </div>
  );
}