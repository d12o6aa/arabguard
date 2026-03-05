// ─── Logs Page ────────────────────────────────────────────────────────────────
import { motion } from "framer-motion";
import { ThreatTable } from "../components/dashboard/ThreatTable";
import { useGuard } from "../hooks/useGuard";

export default function LogsPage() {
  const { threats, feedLoading, refreshFeed } = useGuard();

  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
      <ThreatTable threats={threats} onRefresh={refreshFeed} loading={feedLoading} />
    </motion.div>
  );
}
