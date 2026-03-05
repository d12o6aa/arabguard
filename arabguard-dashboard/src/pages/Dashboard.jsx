// ─── Dashboard Page ───────────────────────────────────────────────────────────
import { motion } from "framer-motion";
import { Activity, XCircle, AlertTriangle, TrendingUp, Brain } from "lucide-react";
import { StatCard } from "../components/common/Card";
import { ThreatTable } from "../components/dashboard/ThreatTable";
import { PIIVisualizer } from "../components/dashboard/PIIVisualizer";
import { LanguageRadarChart, AttackTypeChart, ThreatTimeline } from "../components/dashboard/Charts";
import { GuardrailToggles } from "../components/dashboard/GuardrailToggles";
import { ScannerPanel } from "../components/dashboard/ScannerPanel";
import { useGuard } from "../hooks/useGuard";
import { usePolicies } from "../hooks/usePolicies";

const stagger = {
  hidden: {},
  show: { transition: { staggerChildren: 0.07 } },
};
const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.4, ease: "easeOut" } },
};

export default function DashboardPage() {
  const {
    threats, feedLoading, refreshFeed,
    stats,
    scanInput, setScanInput, scan, scanResult, scanLoading, scanError, clearScan,
  } = useGuard();

  const { policies, togglePolicy, updating, activeCount } = usePolicies();

  return (
    <motion.div variants={stagger} initial="hidden" animate="show" className="space-y-4">

      {/* ── Stat Cards ── */}
      <motion.div variants={fadeUp} className="grid grid-cols-5 gap-3">
        <StatCard label="Total Requests"   value={stats.totalRequests?.toLocaleString()} sub="This session"    icon={Activity}      color="blue"   trend="+12%" />
        <StatCard label="Blocked"          value={stats.totalBlocked}                     sub="Injections"      icon={XCircle}       color="red" />
        <StatCard label="Flagged"          value={stats.totalFlagged}                     sub="Needs review"    icon={AlertTriangle} color="orange" />
        <StatCard label="Threat Rate"      value={`${stats.threatRate}%`}                 sub="Of all requests" icon={TrendingUp}    color="purple" />
        <StatCard label="AI Accuracy"      value={`${stats.aiAccuracy}%`}                 sub="MARBERT model"   icon={Brain}         color="green"  trend="↑0.3%" />
      </motion.div>

      {/* ── Main Grid ── */}
      <div className="grid grid-cols-3 gap-4">

        {/* Left column (2/3) */}
        <div className="col-span-2 space-y-4">
          <motion.div variants={fadeUp}>
            <ThreatTable threats={threats} onRefresh={refreshFeed} loading={feedLoading} />
          </motion.div>

          <motion.div variants={fadeUp}>
            <PIIVisualizer />
          </motion.div>

          <motion.div variants={fadeUp} className="grid grid-cols-2 gap-4">
            <LanguageRadarChart />
            <AttackTypeChart />
          </motion.div>

          <motion.div variants={fadeUp}>
            <ThreatTimeline />
          </motion.div>
        </div>

        {/* Right column (1/3) */}
        <div className="col-span-1 space-y-4">
          <motion.div variants={fadeUp}>
            <ScannerPanel
              input={scanInput}
              setInput={setScanInput}
              onScan={scan}
              result={scanResult}
              loading={scanLoading}
              error={scanError}
              onClear={clearScan}
            />
          </motion.div>

          <motion.div variants={fadeUp}>
            <GuardrailToggles
              policies={policies}
              onToggle={togglePolicy}
              updating={updating}
              activeCount={activeCount}
            />
          </motion.div>
        </div>
      </div>
    </motion.div>
  );
}
