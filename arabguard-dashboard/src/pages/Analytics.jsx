// ─── Analytics Page ───────────────────────────────────────────────────────────
import { motion } from "framer-motion";
import { LanguageRadarChart, AttackTypeChart, ThreatTimeline } from "../components/dashboard/Charts";

const stagger = { hidden: {}, show: { transition: { staggerChildren: 0.1 } } };
const fadeUp  = { hidden: { opacity: 0, y: 16 }, show: { opacity: 1, y: 0, transition: { duration: 0.4 } } };

export default function AnalyticsPage() {
  return (
    <motion.div variants={stagger} initial="hidden" animate="show" className="space-y-4">
      <motion.div variants={fadeUp}>
        <ThreatTimeline />
      </motion.div>
      <motion.div variants={fadeUp} className="grid grid-cols-2 gap-4">
        <LanguageRadarChart />
        <AttackTypeChart />
      </motion.div>
    </motion.div>
  );
}
