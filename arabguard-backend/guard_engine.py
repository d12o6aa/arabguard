"""
guard_engine.py
===============
Application-level wrapper around the ``arabguard`` SDK.

What this file owns
-------------------
- ``GuardEngine`` — loads the SDK once, delegates all analysis to it.
- ``AnalyticsStore`` — rolling in-memory store + JSONL persistence.
- Language / vector classifiers — enrich the SDK result with dashboard metadata.

What this file does NOT own
----------------------------
- Score calculation      → SDK's pipeline.normalize_and_detect()
- Decision logic         → SDK's ArabGuard.analyze()
- AI inference           → SDK's ArabGuard._ai_predict()

Data flow: SDK result → guard_engine.analyze()
----------------------------------------------
1. ``guard_result = self.guard.analyze(text)``   # SDK runs all 4 layers
2. ``d = guard_result.to_dict()``                # snake_case fields
3. ``d.update({...})``                           # add dashboard metadata
   Fields added here:
     id, timestamp, raw, status, risk, vector,
     decision_source, lang_dist,
     ai_confidence (explicit copy — ensures it is always in d),
     ai_prediction (explicit copy)
4. ``self.analytics.record(d)``                  # persist + counters
5. return d                                      # consumed by schemas.py

save_for_retraining format
--------------------------
Matches the original training dataset structure:

    {
        "id":              str,
        "text":            str,        # raw user input
        "normalized_text": str,        # after deobfuscation
        "label":           1,          # reviewer confirmed malicious
        "score":           int,        # final risk score 0-300
        "ai_score":        int,        # int(ai_confidence × 300)
        "ai_confidence":   float,      # MARBERT confidence
        "ai_prediction":   int,        # 0 | 1
        "vector":          str,        # attack vector label
        "dialect":         str,        # franco | egyptian | msa | english | mixed
        "intent_goal":     str,        # human-readable attack intent
        "notes":           str,        # reviewer free-text
        "saved_at":        str,        # ISO-8601 UTC timestamp
    }
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

from config import Settings

logger = logging.getLogger("arabguard.engine")


# ─────────────────────────────────────────────────────────────────────────────
# LANGUAGE CLASSIFIER  (radar chart data)
# ─────────────────────────────────────────────────────────────────────────────

_FRANCO_RE = re.compile(
    r"\b(?:[a-zA-Z]*[23578][a-zA-Z]*)+\b"
    r"|\b(?:momken|keda|mesh|msh|wala|kol|lel|3ala|bta3|ela|deh|da|di"
    r"|ana|enta|enti|hwa|hya|homa|tab|ya3ny|bas|mafeesh|mafesh"
    r"|3ayez|3arif|delwa2ty|khalik|t2oly|2oly|leeh|ezay|feen|meen)\b",
    re.IGNORECASE,
)
_ARABIC_RE      = re.compile(r"[\u0600-\u06FF]")
_UNICODE_OBF_RE = re.compile(r"[\u0400-\u04FF\u0370-\u03FF\u2100-\u214F]")
_BASE64_HEX_RE  = re.compile(r"(?:[A-Za-z0-9+/=]{20,}|[0-9a-fA-F]{16,})")

_EGYPTIAN_MARKERS = frozenset({
    "ايه", "إيه", "ازاي", "ازيك", "كده", "كدا", "مش", "عايز",
    "عارف", "دلوقتي", "دلوقت", "اهو", "اهي", "يعني", "بقى",
    "بقي", "ماشي", "تمام", "بصراحه", "صاحبي", "يلا", "اللي",
    "بتاع", "بتاعت", "بتاعة", "عشان", "علشان", "اوك",
})


def classify_language(text: str) -> Dict[str, float]:
    """Return per-language scores (0–100) for the radar chart."""
    has_arabic  = bool(_ARABIC_RE.search(text))
    has_franco  = bool(_FRANCO_RE.search(text))
    has_unicode = bool(_UNICODE_OBF_RE.search(text))
    has_encoded = bool(_BASE64_HEX_RE.search(text))
    has_english = bool(re.search(r"[a-zA-Z]{3,}", text))

    lower      = text.lower()
    egypt_hits = sum(1 for m in _EGYPTIAN_MARKERS if m in lower)

    return {
        "msa":      60.0 if has_arabic and egypt_hits == 0 else (20.0 if has_arabic else 0.0),
        "egyptian": min(egypt_hits * 25.0, 90.0) if has_arabic else 0.0,
        "franco":   80.0 if has_franco  else 0.0,
        "english":  55.0 if (has_english and not has_arabic) else (15.0 if has_english else 0.0),
        "unicode":  85.0 if has_unicode else 0.0,
        "encoded":  85.0 if has_encoded else 0.0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK VECTOR CLASSIFIER  (bar chart data)
# ─────────────────────────────────────────────────────────────────────────────

VECTOR_COLORS: Dict[str, str] = {
    "Ignore Instructions":     "#f43f5e",
    "Dialect-Based Jailbreak": "#60a5fa",
    "Role Hijack":             "#fb923c",
    "Prompt Leak":             "#facc15",
    "Data Exfiltration":       "#a78bfa",
    "PII Extraction":          "#34d399",
    "Encoding Attack":         "#f97316",
    "None":                    "#52525b",
}

_PATTERN_TO_VECTOR: List[Tuple[str, str]] = [
    (r"تجاهل|انسى|انسي|ignore|cancel|disregard|skip|forget|nevermind",
     "Ignore Instructions"),
    (r"DAN|jailbreak|god.?mode|5alinak|خليك.*حر|msh.*bound|مش.*ملزم",
     "Dialect-Based Jailbreak"),
    (r"act.as|role.?play|you.?are.?now|pretend|تصرف.ك|انت.الان|كن.الان",
     "Role Hijack"),
    (r"show.*prompt|reveal.*prompt|print.*prompt|repeat.*instruction"
     r"|كرر.*تعليم|اظهر.*برومبت|ورينى.*برومبت|ما.*تعليماتك",
     "Prompt Leak"),
    (r"leak|extract|exfiltrate|dump.*data|print.*data|سرب|استخرج",
     "Data Exfiltration"),
    (r"national.?id|password|رقم.قومي|باسورد|كلمة.*سر|رقم.*تليفون|credit.?card",
     "PII Extraction"),
    (r"base64|hex|rot.?13|\x5cx[0-9a-f]{2}|%[0-9a-f]{2}",
     "Encoding Attack"),
]


def classify_vector(matched_pattern: Optional[str], raw_text: str) -> str:
    corpus = (matched_pattern or "") + " " + raw_text
    for pat, label in _PATTERN_TO_VECTOR:
        if re.search(pat, corpus, re.IGNORECASE | re.DOTALL):
            return label
    return "None"


def risk_from_score(score: int) -> str:
    if score >= 200: return "CRITICAL"
    if score >= 120: return "HIGH"
    if score >= 80:  return "MEDIUM"
    return "LOW"


def decision_source_label(result_dict: dict) -> str:
    """Produce 'AI+Regex', 'AI', 'Regex', or 'Pipeline' from a result dict."""
    ai_used   = result_dict.get("ai_prediction") is not None
    regex_hit = bool(result_dict.get("matched_pattern"))
    if ai_used and regex_hit: return "AI+Regex"
    if ai_used:               return "AI"
    if regex_hit:             return "Regex"
    return "Pipeline"


# ─────────────────────────────────────────────────────────────────────────────
# ANALYTICS STORE
# ─────────────────────────────────────────────────────────────────────────────

_LANG_LABELS: Dict[str, str] = {
    "msa":      "MSA",
    "egyptian": "Egyptian",
    "franco":   "Franco",
    "english":  "English",
    "unicode":  "Unicode",
    "encoded":  "Encoded",
}


class AnalyticsStore:
    """Rolling in-memory store (last MAX_ENTRIES) + JSONL persistence."""

    MAX_ENTRIES = 10_000

    def __init__(self, log_file: str):
        self._log_path      = Path(log_file)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log:           Deque[dict]      = deque(maxlen=self.MAX_ENTRIES)
        self._vector_counts: Dict[str, int]   = defaultdict(int)
        self._lang_acc:      Dict[str, float] = defaultdict(float)
        self._lang_n:        int              = 0
        self._load_existing()

    def _load_existing(self):
        if not self._log_path.exists():
            logger.info("Analytics: no existing log at %s — fresh start", self._log_path)
            return
        loaded = 0
        try:
            with self._log_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self._ingest(json.loads(line), persist=False)
                        loaded += 1
                    except (json.JSONDecodeError, Exception):
                        pass
            logger.info("Analytics: replayed %d entries from %s", loaded, self._log_path)
        except OSError as exc:
            logger.warning("Analytics: could not load log — %s", exc)

    def _ingest(self, entry: dict, persist: bool = True):
        self._log.append(entry)
        self._vector_counts[entry.get("vector", "None")] += 1
        for k, v in (entry.get("lang_dist") or {}).items():
            self._lang_acc[k] += float(v)
        self._lang_n += 1
        if persist:
            try:
                with self._log_path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
            except OSError as exc:
                logger.warning("Analytics: write failed — %s", exc)

    def record(self, entry: dict):
        self._ingest(entry, persist=True)

    @property
    def all_entries(self) -> List[dict]:
        return list(self._log)

    def total(self) -> int:
        return len(self._log)

    def count_by_status(self, status: str) -> int:
        return sum(1 for e in self._log if e.get("status", "").upper() == status.upper())

    def language_distribution(self) -> List[dict]:
        """Recharts RadarChart: [ { "subject": "MSA", "value": 42.0 }, … ]"""
        axes = ["msa", "egyptian", "franco", "english", "unicode", "encoded"]
        if self._lang_n == 0:
            return [{"subject": _LANG_LABELS[k], "value": 0.0} for k in axes]
        return [
            {
                "subject": _LANG_LABELS[k],
                "value":   round(self._lang_acc.get(k, 0.0) / self._lang_n, 1),
            }
            for k in axes
        ]

    def attack_breakdown(self) -> List[dict]:
        """Recharts BarChart: [ { "name": "…", "count": 7, "color": "…" }, … ]"""
        return [
            {"name": k, "count": v, "color": VECTOR_COLORS.get(k, "#888")}
            for k, v in sorted(self._vector_counts.items(), key=lambda x: -x[1])
            if k != "None"
        ]

    def timeline(self, window_hours: int = 24) -> List[dict]:
        now       = datetime.now(timezone.utc)
        start     = now - timedelta(hours=window_hours)
        slot_mins = max((window_hours * 60) // 10, 1)
        slots: List[dict] = []
        for i in range(10):
            slot_start = start + timedelta(minutes=i * slot_mins)
            slot_end   = slot_start + timedelta(minutes=slot_mins)
            counts     = {"blocked": 0, "flagged": 0, "safe": 0}
            for e in self._log:
                try:
                    raw_ts = e.get("timestamp", "")
                    ts = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    if slot_start <= ts < slot_end:
                        s = e.get("status", "SAFE").upper()
                        if s == "BLOCKED":   counts["blocked"] += 1
                        elif s == "FLAGGED": counts["flagged"] += 1
                        else:                counts["safe"]    += 1
                except Exception:
                    pass
            slots.append({"time": slot_start.strftime("%H:%M"), **counts})
        return slots


# ─────────────────────────────────────────────────────────────────────────────
# GUARD ENGINE  — clean SDK wrapper
# ─────────────────────────────────────────────────────────────────────────────

class GuardEngine:
    """
    Application-level singleton.

    Lifecycle
    ---------
    1. Instantiated in main.py lifespan().
    2. engine.load() → ArabGuard(use_ai=True) — called once on startup.
    3. engine.analyze(text) → delegates to self.guard.analyze(text),
       then enriches the result with dashboard metadata.

    The engine never recalculates scores or decisions — the SDK owns that.
    """

    def __init__(self, settings: Settings):
        self._settings   = settings
        self._guard      = None          # ArabGuard SDK instance
        self.analytics   = AnalyticsStore(settings.analytics_log_file)
        self.model_ready = False
        self._retrain_path = (
            Path(settings.analytics_log_file).parent / "retraining_set.jsonl"
        )

    # ── Startup ───────────────────────────────────────────────────────────────

    def load(self) -> None:
        """
        Load the ArabGuard SDK.  Called once from lifespan() in main.py.

        Passes all configuration to ArabGuard(); the SDK handles device
        selection, model download, and graceful fallback if transformers
        is unavailable.
        """
        from arabguard import ArabGuard

        device = None if self._settings.device == "auto" else self._settings.device

        logger.info(
            "Loading ArabGuard SDK — use_ai=%s  model=%s  device=%s",
            self._settings.use_ai,
            self._settings.model_id,
            device or "auto-detect",
        )

        self._guard = ArabGuard(
            use_ai                 = self._settings.use_ai,
            ai_model_name          = self._settings.model_id,
            block_on_flag          = self._settings.block_on_flag,
            custom_score_threshold = (
                self._settings.block_threshold
                if self._settings.block_threshold != 120
                else None
            ),
            device = device,
        )
        self.model_ready = True

        ai_status  = "enabled" if self._guard.use_ai else "disabled (transformers not found)"
        device_str = getattr(self._guard, "_device", "N/A") or "N/A"
        logger.info(
            "ArabGuard ready — AI: %s  device: %s",
            ai_status, device_str,
        )

        if self._settings.use_ai and not self._guard.use_ai:
            logger.warning(
                "AI was requested but transformers/torch is not installed. "
                "Running in regex-only mode.  "
                "Fix: pip install 'arabguard[ai]'"
            )

    # ── Analysis ──────────────────────────────────────────────────────────────

    def analyze(
        self,
        text           : str,
        use_ai_override: Optional[bool] = None,
    ) -> dict:
        """
        Analyze a single text.

        1. Delegates to ArabGuard.analyze(text) — runs all 4 layers.
        2. Converts GuardResult → plain dict via to_dict().
        3. Enriches with dashboard metadata (id, timestamp, vector, …).
        4. Explicitly copies ai_confidence and ai_prediction so they are
           guaranteed to be present in d even if to_dict() changes.
        5. Records to AnalyticsStore.

        Returns
        -------
        dict
            All fields required by GuardResultResponse in schemas.py,
            plus dashboard-specific metadata.
        """
        if not self._guard:
            raise RuntimeError(
                "GuardEngine.load() must be called before analyze()."
            )

        # Temporarily override AI setting if caller requests it
        original_use_ai = self._guard.use_ai
        if use_ai_override is not None:
            # Only enable AI if the model is actually loaded
            self._guard.use_ai = use_ai_override and bool(self._guard._model)
        try:
            # ── Delegate entirely to the SDK ─────────────────────────────
            guard_result = self._guard.analyze(text)
        finally:
            self._guard.use_ai = original_use_ai

        # ── Convert SDK result → plain dict ──────────────────────────────
        # to_dict() returns:
        #   decision, score, is_blocked, is_flagged, normalized_text,
        #   matched_pattern, all_matched_patterns, pipeline_steps,
        #   reason, ai_confidence, ai_prediction
        d = guard_result.to_dict()

        # ── Explicit ai_confidence / ai_prediction copy ───────────────────
        # These fields come from the SDK but we copy them explicitly so:
        # a) they are guaranteed present in d for the dashboard
        # b) d.update() below doesn't accidentally overwrite them
        # (to_dict already includes them, this is a defensive explicit pass)
        ai_confidence = guard_result.ai_confidence   # float | None
        ai_prediction = guard_result.ai_prediction   # int   | None

        # ── Dashboard metadata ────────────────────────────────────────────
        status = (
            "BLOCKED" if d["is_blocked"] else
            "FLAGGED" if d["is_flagged"] else
            "SAFE"
        )
        lang_dist = classify_language(text)
        vector    = classify_vector(d.get("matched_pattern"), text)

        d.update({
            "id":              str(uuid.uuid4()),
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "raw":             text,
            "status":          status,
            "risk":            risk_from_score(d["score"]),
            "vector":          vector,
            "decision_source": decision_source_label(d),
            "lang_dist":       lang_dist,
            # Explicit pass-through so schemas.py can always read these
            # (they are already in d from to_dict, but being explicit avoids
            # confusion if field names ever drift)
            "ai_confidence":   ai_confidence,
            "ai_prediction":   ai_prediction,
        })

        self.analytics.record(d)

        logger.debug(
            "analyze() → %s  score=%d  ai_conf=%s  vector=%s",
            d["decision"],
            d["score"],
            f"{ai_confidence:.3f}" if ai_confidence is not None else "N/A",
            vector,
        )

        return d

    def analyze_batch(self, texts: List[str], use_ai: bool = True) -> List[dict]:
        return [self.analyze(t, use_ai_override=use_ai) for t in texts]

    # ── Retraining ────────────────────────────────────────────────────────────

    def save_for_retraining(self, entry: dict, notes: str = "") -> None:
        """
        Append a reviewed entry to ``retraining_set.jsonl``.

        Format matches the original training dataset:

            text, normalized_text, label, score, ai_score,
            ai_confidence, ai_prediction, vector, dialect,
            intent_goal, notes, saved_at

        ``dialect`` and ``intent_goal`` are read from ``pipeline_steps``
        which are computed in ArabGuard.analyze() and forwarded here
        through the entry dict.
        """
        steps = entry.get("pipeline_steps") or {}

        # ai_score = int(confidence × 300) — stored in pipeline_steps by core.py
        ai_score = steps.get("ai_raw_score") or (
            int((entry.get("ai_confidence") or 0) * 300)
            if entry.get("ai_prediction") == 1
            else 0
        )

        record = {
            "id":              entry.get("id"),
            "text":            entry.get("raw", ""),
            "normalized_text": entry.get("normalized_text", ""),
            "label":           1,                           # reviewer confirmed malicious
            "score":           entry.get("score"),
            "ai_score":        ai_score,
            "ai_confidence":   entry.get("ai_confidence"),  # float | None
            "ai_prediction":   entry.get("ai_prediction"),  # 0 | 1 | None
            "vector":          entry.get("vector", "None"),
            # dialect & intent_goal come from pipeline_steps (set in core.py)
            "dialect":         steps.get("dialect",     "unknown"),
            "intent_goal":     steps.get("intent_goal", "Unknown / Semantic attack"),
            "notes":           notes,
            "saved_at":        datetime.now(timezone.utc).isoformat(),
        }

        try:
            with self._retrain_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
            logger.info(
                "Retraining: saved %s  dialect=%s  intent=%s  ai_conf=%s",
                entry.get("id"),
                record["dialect"],
                record["intent_goal"],
                f"{record['ai_confidence']:.3f}" if record["ai_confidence"] is not None else "N/A",
            )
        except OSError as exc:
            logger.warning("Retraining: write failed — %s", exc)

    # ── Properties (read by /health endpoint in main.py) ─────────────────────

    @property
    def guard(self):
        """Direct access to the ArabGuard SDK instance."""
        return self._guard


# Module-level slot — populated by lifespan() in main.py
engine: Optional[GuardEngine] = None