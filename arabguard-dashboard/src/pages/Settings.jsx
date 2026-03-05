// ─── Settings Page ────────────────────────────────────────────────────────────
import { useState } from "react";
import { motion } from "framer-motion";
import { Settings, Save, Key, Brain, Cpu } from "lucide-react";
import { Card, CardHeader, CardBody } from "../components/common/Card";
import { GuardrailToggles } from "../components/dashboard/GuardrailToggles";
import { Button } from "../components/common/Buttons";
import { Input } from "../components/common/Input";
import { usePolicies } from "../hooks/usePolicies";

export default function SettingsPage() {
  const { policies, togglePolicy, updating, activeCount } = usePolicies();
  const [saved, setSaved] = useState(false);
  const [apiUrl, setApiUrl] = useState(import.meta.env.VITE_API_BASE_URL || "http://localhost:8000");
  const [hfToken, setHfToken] = useState(import.meta.env.VITE_HF_API_TOKEN || "");

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="space-y-5 max-w-3xl">

      <Card>
        <CardHeader title="API Configuration" icon={Key} iconColor="text-amber-400" />
        <CardBody className="space-y-4">
          <div>
            <label className="text-xs font-mono text-zinc-500 uppercase tracking-wider block mb-1.5">FastAPI Backend URL</label>
            <Input
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              placeholder="http://localhost:8000"
              className="font-mono"
            />
          </div>
          <div>
            <label className="text-xs font-mono text-zinc-500 uppercase tracking-wider block mb-1.5">Hugging Face API Token</label>
            <Input
              type="password"
              value={hfToken}
              onChange={(e) => setHfToken(e.target.value)}
              placeholder="hf_xxxxxxxxxxxxxxxxxxxx"
              className="font-mono"
            />
            <p className="text-xs text-zinc-700 mt-1.5 font-mono">
              Used for direct HF inference fallback. Get token from{" "}
              <a href="https://huggingface.co/settings/tokens" className="text-violet-400 hover:underline">huggingface.co/settings/tokens</a>
            </p>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Model Configuration" icon={Brain} iconColor="text-violet-400" />
        <CardBody className="space-y-3">
          {[
            { label: "Model ID",       value: "d12o6aa/ArabGuard",    note: "Hugging Face model identifier" },
            { label: "Base Model",     value: "UBC-NLP/MARBERT",       note: "Arabic BERT base architecture" },
            { label: "AI Threshold",   value: "Score 60–119",          note: "Range that triggers AI layer" },
            { label: "Block Conf.",    value: "≥ 0.75",                note: "AI confidence to BLOCK" },
            { label: "Flag Conf.",     value: "≥ 0.55",                note: "AI confidence to FLAG" },
          ].map(({ label, value, note }) => (
            <div key={label} className="flex items-center justify-between py-2 border-b border-zinc-800/30 last:border-0">
              <div>
                <p className="text-xs font-mono text-zinc-400">{label}</p>
                <p className="text-[10px] text-zinc-700 mt-0.5">{note}</p>
              </div>
              <code className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded-lg">{value}</code>
            </div>
          ))}
        </CardBody>
      </Card>

      <GuardrailToggles policies={policies} onToggle={togglePolicy} updating={updating} activeCount={activeCount} />

      <Button
        variant="primary"
        icon={Save}
        onClick={handleSave}
        className="w-full"
      >
        {saved ? "Saved ✓" : "Save Configuration"}
      </Button>
    </motion.div>
  );
}
