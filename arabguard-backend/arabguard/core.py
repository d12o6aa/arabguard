"""
arabguard/core.py
=================
Main entry point for the ArabGuard SDK.

Pipeline — strict 3-phase execution
-------------------------------------
  PHASE 1 │ NORMALIZATION
          │  normalize_and_detect(raw_text, debug=True)
          │  → normalized_text, base_score, steps{intent/code/arabic/keyword scores}
          │
  PHASE 2 │ REGEX  (runs on NORMALIZED text only)
          │  ArabicRegexSecurityLayer  ← per-group matching + categorization
          │  RegexSecurityLayer        ← per-group matching + categorization
          │  → matched patterns, category labels, regex score bump
          │
  PHASE 3 │ MARBERT AI  (conditional)
          │  Activates only when:
          │    • 80 ≤ final_score ≤ 120, OR
          │    • decision is FLAG or BLOCKED
          │  → ai_prediction (0/1), ai_confidence (0.0–1.0)

pipeline_steps schema (forwarded to dashboard)
-----------------------------------------------
  # — Phase 1 ——————————————————————————————————————————
  "phase_1_normalization": {
      "raw_input":           str,   # original text
      "normalized_text":     str,   # after deobfuscation
      "intent_score":        int,   # sanitize_malicious_code_intent()
      "code_score":          int,   # analyze_code_patterns()
      "arabic_kw_score":     int,   # detect_arabic_injection()
      "keyword_score":       int,   # dangerous keyword scan
      "base_score":          int,   # sum of above (pre-regex)
      "pipeline_decision":   str,   # SAFE|FLAG|BLOCKED from pipeline alone
      "transformations":     list,  # which transforms fired (base64, hex, …)
  }

  # — Phase 2 ——————————————————————————————————————————
  "phase_2_regex": {
      "ran_on":              str,   # "normalized_text"
      "arabic": {
          "fired":           bool,
          "category":        str,   # e.g. "ignore_instructions"
          "match_count":     int,
          "matched_patterns":list,  # up to 3 truncated pattern strings
      },
      "english": {
          "fired":           bool,
          "category":        str,
          "match_count":     int,
          "matched_patterns":list,
      },
      "regex_score_bump":    int,   # score added by regex hits
      "score_after_regex":   int,
      "decision_after_regex":str,
  }

  # — Phase 3 ——————————————————————————————————————————
  "phase_3_ai": {
      "activated":           bool,
      "reason":              str,   # why AI was / was not activated
      "prediction":          int|None,   # 0=safe, 1=malicious
      "confidence":          float|None, # 0.0–1.0
      "label":               str|None,   # "MALICIOUS"|"SAFE"|None
      "score_contribution":  int,        # score bump from AI (if any)
      "decision_after_ai":   str,
  }

  # — Final ————————————————————————————————————————————
  "final_score":             int,
  "final_decision":          str,
"""

from __future__ import annotations

import logging
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .pipeline        import normalize_and_detect
from .security_layers import (
    ArabicRegexSecurityLayer,
    RegexSecurityLayer,
    CombinedSecurityLayer,
)

logger = logging.getLogger("arabguard.core")

# ── AI dependency check ────────────────────────────────────────────────────────
_TRANSFORMERS_AVAILABLE = False
_TORCH_AVAILABLE        = False
AutoTokenizer                      = None   # type: ignore[assignment]
AutoModelForSequenceClassification = None   # type: ignore[assignment]
torch                              = None   # type: ignore[assignment]

try:
    import torch as _torch
    _TORCH_AVAILABLE = True
    torch = _torch
    logger.debug("torch %s imported", _torch.__version__)
except ImportError as _e:
    logger.warning(
        "torch not found (%s) — AI layer will be disabled. "
        "Install: pip install torch", _e,
    )

try:
    from transformers import (
        AutoTokenizer                      as _AT,
        AutoModelForSequenceClassification as _AM,
    )
    AutoTokenizer                      = _AT   # type: ignore[assignment]
    AutoModelForSequenceClassification = _AM   # type: ignore[assignment]
    _TRANSFORMERS_AVAILABLE            = True
    logger.debug("transformers imported")
except ImportError as _e:
    logger.warning(
        "transformers not found (%s) — AI layer will be disabled. "
        "Install: pip install transformers scipy", _e,
    )

AI_DEPS_AVAILABLE: bool = _TRANSFORMERS_AVAILABLE and _TORCH_AVAILABLE


# ─────────────────────────────────────────────────────────────────────────────
# PATTERN → CATEGORY MAP  (for readable dashboard labels)
# ─────────────────────────────────────────────────────────────────────────────

# Map each security_layers group attribute → human-readable category label
_ARABIC_GROUP_LABELS: Dict[str, str] = {
    "basic_ignore_patterns":         "Ignore / Cancel Instructions",
    "arabic_role_change_patterns":   "Role Change / Hijack",
    "arabic_system_access_patterns": "System Access / Prompt Leak",
    "arabic_jailbreak_patterns":     "Jailbreak Trigger",
    "arabic_sensitive_info_patterns":"Sensitive Information Request",
    "arabic_adversarial_patterns":   "Adversarial Manipulation",
    "arabic_force_answer_patterns":  "Force-Answer Attempt",
}

_ENGLISH_GROUP_LABELS: Dict[str, str] = {
    "ignore_patterns":      "Ignore / Override Instructions",
    "role_change_patterns": "Role Change / Hijack",
    "system_access_patterns": "System Access",
    "prompt_leaking_patterns": "Prompt Leak",
    "jailbreak_patterns":   "Jailbreak Trigger",
    "context_manipulation": "Context Manipulation",
    "sensitive_info_patterns": "Sensitive Information",
    "adversarial_patterns": "Adversarial Manipulation",
    "stealthy_patterns":    "Stealthy Injection",
    "exfiltration_patterns":"Data Exfiltration",
    "multi_turn_patterns":  "Multi-Turn Attack",
    "obfuscation_patterns": "Obfuscation",
    "encoding_patterns":    "Encoding Attack",
}


def _categorize_match(
    pattern: str,
    layer_instance: Any,
    group_labels: Dict[str, str],
) -> str:
    """
    Walk the layer's named pattern groups to find which group contains
    ``pattern``, then return the human-readable category label.
    Falls back to "Unknown Pattern" if not found.
    """
    for attr, label in group_labels.items():
        group = getattr(layer_instance, attr, [])
        if pattern in group:
            return label
    return "Unknown Pattern"


def _truncate_pattern(p: str, maxlen: int = 60) -> str:
    """Truncate a raw regex string for safe dashboard display."""
    if len(p) <= maxlen:
        return p
    return p[:maxlen] + "…"


def _detect_transformations(raw: str, normalized: str) -> List[str]:
    """
    Compare raw vs normalized text and report which transforms were applied.
    Used to populate pipeline_steps.phase_1_normalization.transformations.
    """
    transforms: List[str] = []

    # Base64 decode
    if re.search(r"[A-Za-z0-9+/=]{12,}", raw):
        if normalized != raw:
            transforms.append("base64_decode")

    # Hex decode
    if re.search(r"\b[0-9a-fA-F]{8,}\b", raw):
        transforms.append("hex_decode")

    # Unicode normalization (NFKC)
    import unicodedata
    if unicodedata.normalize("NFKC", raw) != raw:
        transforms.append("unicode_nfkc")

    # HTML entities
    import html as _html
    if _html.unescape(raw) != raw:
        transforms.append("html_unescape")

    # Split-letter merging (heuristic: single chars separated by spaces)
    if re.search(r"(?:\b[A-Za-z]\b\s+){3,}", raw):
        transforms.append("split_letter_merge")

    # Excessive char repetition
    if re.search(r"(.)\1{3,}", raw):
        transforms.append("repetition_collapse")

    # Arabic normalization (different alef forms etc.)
    arabic_variants = re.compile(r"[آأإٱ]")
    if arabic_variants.search(raw):
        transforms.append("arabic_normalize")

    return transforms if transforms else ["none"]


# ─────────────────────────────────────────────────────────────────────────────
# GUARD RESULT DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GuardResult:
    """
    Full analysis result returned by :meth:`ArabGuard.analyze`.

    decision             "SAFE" | "FLAG" | "BLOCKED"
    score                0–300
    is_blocked           decision == "BLOCKED"
    is_flagged           decision in {"FLAG", "BLOCKED"}
    normalized_text      text after full deobfuscation pipeline
    matched_pattern      first regex match, or None
    all_matched_patterns all matched regex strings
    pipeline_steps       rich per-phase breakdown (see module docstring)
    reason               human-readable explanation
    ai_confidence        MARBERT confidence 0.0–1.0, None if AI not used
    ai_prediction        0=safe, 1=malicious, None if AI not used
    """
    decision            : str
    score               : int
    is_blocked          : bool
    is_flagged          : bool
    normalized_text     : str
    matched_pattern     : Optional[str]   = field(default=None)
    all_matched_patterns: List[str]       = field(default_factory=list)
    pipeline_steps      : Dict[str, Any]  = field(default_factory=dict)
    reason              : str             = ""
    ai_confidence       : Optional[float] = field(default=None)
    ai_prediction       : Optional[int]   = field(default=None)

    def __bool__(self) -> bool:
        return not self.is_flagged

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision":             self.decision,
            "score":                self.score,
            "is_blocked":           self.is_blocked,
            "is_flagged":           self.is_flagged,
            "normalized_text":      self.normalized_text,
            "matched_pattern":      self.matched_pattern,
            "all_matched_patterns": self.all_matched_patterns,
            "pipeline_steps":       self.pipeline_steps,
            "reason":               self.reason,
            "ai_confidence":        self.ai_confidence,
            "ai_prediction":        self.ai_prediction,
        }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ArabGuard:
    """
    Multi-layer Arabic/English prompt-injection and jailbreak detector.

    Detection pipeline — 3 strict phases
    -------------------------------------
    Phase 1  Normalization
             Deobfuscates the raw text, runs keyword / intent / code scoring.
             Produces: normalized_text, base_score, preliminary decision.

    Phase 2  Regex  (on normalized text)
             Runs Arabic and English regex layers on the NORMALIZED text.
             Per-group categorization is stored in pipeline_steps.
             Produces: matched patterns, regex score bump, updated decision.

    Phase 3  MARBERT AI  (conditional)
             Activates only when:  80 ≤ score ≤ 120  OR  decision is FLAG/BLOCKED.
             Produces: ai_prediction, ai_confidence, final decision.

    Parameters
    ----------
    use_ai : bool
        Enable MARBERT AI layer.  Default ``True``.
        Falls back to ``False`` gracefully if deps are missing.
    ai_model_name : str
        HuggingFace model id.  Default ``"d12o6aa/ArabGuard"``.
    block_on_flag : bool
        Treat FLAG as BLOCKED (strict mode).  Default ``False``.
    custom_score_threshold : Optional[int]
        Override default BLOCKED threshold (120).
    device : Optional[str]
        ``"cpu"`` | ``"cuda"`` | ``"mps"`` | ``None`` (auto-detect).
    """

    def __init__(
        self,
        use_ai                : bool           = True,
        ai_model_name         : str            = "d12o6aa/ArabGuard",
        block_on_flag         : bool           = False,
        custom_score_threshold: Optional[int]  = None,
        device                : Optional[str]  = None,
    ):
        self.block_on_flag          = block_on_flag
        self.custom_score_threshold = custom_score_threshold
        self.ai_model_name          = ai_model_name

        # Regex layers
        self._arabic   = ArabicRegexSecurityLayer()
        self._english  = RegexSecurityLayer()
        self._combined = CombinedSecurityLayer()

        # AI model state — always defined even when disabled
        self._tokenizer: Any           = None
        self._model    : Any           = None
        self._device   : Optional[str] = None

        if use_ai and not AI_DEPS_AVAILABLE:
            warnings.warn(
                "ArabGuard: use_ai=True but transformers/torch are not installed. "
                "AI layer disabled. "
                f"(transformers={_TRANSFORMERS_AVAILABLE}, torch={_TORCH_AVAILABLE}) "
                "Fix: pip install 'arabguard[ai]'",
                RuntimeWarning,
                stacklevel=2,
            )
            self.use_ai = False
        else:
            self.use_ai = use_ai

        if self.use_ai:
            self._load_ai_model(device)

    # ── AI model setup ────────────────────────────────────────────────────────

    def _load_ai_model(self, device: Optional[str] = None) -> None:
        """Load the MARBERT classifier from Hugging Face Hub."""
        try:
            if device is None:
                if torch.cuda.is_available():
                    device = "cuda"
                elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                    device = "mps"
                else:
                    device = "cpu"
            self._device = device

            logger.info(
                "Loading AI model '%s' → device='%s' …",
                self.ai_model_name, self._device,
            )
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.ai_model_name, use_fast=True,
            )
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.ai_model_name,
            )
            self._model.to(self._device)
            self._model.eval()
            logger.info(
                "AI model ready — device=%s  params=%s",
                self._device,
                f"{sum(p.numel() for p in self._model.parameters()):,}",
            )
        except Exception as exc:
            warnings.warn(
                f"ArabGuard: failed to load model '{self.ai_model_name}': {exc}. "
                "AI layer disabled — regex+pipeline will still run.",
                RuntimeWarning,
                stacklevel=3,
            )
            logger.error("AI model load failed: %s", exc, exc_info=True)
            self.use_ai     = False
            self._tokenizer = None
            self._model     = None
            self._device    = None

    # ── AI inference ──────────────────────────────────────────────────────────

    def _ai_predict(self, text: str) -> Tuple[int, float]:
        """
        Run MARBERT inference on ``text``.

        Returns (prediction, confidence)
            prediction : 0 = safe, 1 = malicious
            confidence : 0.0–1.0
        """
        if not self.use_ai or self._model is None:
            return 0, 0.0
        try:
            inputs = self._tokenizer(
                text,
                return_tensors = "pt",
                truncation     = True,
                max_length     = 512,
                padding        = True,
            )
            inputs = {k: v.to(self._device) for k, v in inputs.items()}
            with torch.no_grad():
                logits = self._model(**inputs).logits
                probs  = torch.softmax(logits, dim=-1)
            prediction = int(torch.argmax(probs, dim=-1).item())
            confidence = float(probs[0, prediction].item())
            logger.debug(
                "_ai_predict pred=%d conf=%.3f text=%r",
                prediction, confidence, text[:60],
            )
            return prediction, confidence
        except Exception as exc:
            warnings.warn(
                f"ArabGuard: AI inference failed: {exc}. Defaulting to safe.",
                RuntimeWarning,
                stacklevel=2,
            )
            logger.warning("AI inference error: %s", exc)
            return 0, 0.0

    # ── Public API ────────────────────────────────────────────────────────────

    def check(self, text: str) -> bool:
        """Fast boolean: True = safe, False = blocked/flagged."""
        return not self.analyze(text).is_flagged

    def analyze(self, text: str) -> GuardResult:
        """
        Full 3-phase analysis.

        Returns a GuardResult whose ``pipeline_steps`` dict contains one
        nested section per phase, suitable for professional dashboard display.
        """
        if not isinstance(text, str):
            text = str(text)

        # ══════════════════════════════════════════════════════════════════
        # PHASE 1 — NORMALIZATION
        # ══════════════════════════════════════════════════════════════════
        #
        # normalize_and_detect() runs:
        #   1. sanitize_malicious_code_intent  → intent_score
        #   2. analyze_code_patterns           → code_score
        #   3. detect_arabic_injection         → arabic_kw_score
        #   4-12. unicode/html/emoji/b64/hex/deobfuscate/split/collapse
        #   13. dangerous keyword scoring      → keyword_score
        #
        normalized, base_score, p1_decision, raw_steps = normalize_and_detect(
            text, debug=True
        )

        # Apply custom score threshold before regex
        if self.custom_score_threshold is not None:
            if base_score >= self.custom_score_threshold:
                p1_decision = "BLOCKED"
            elif p1_decision == "BLOCKED":
                p1_decision = "FLAG"

        transformations = _detect_transformations(text, normalized)

        phase1: Dict[str, Any] = {
            "raw_input":         text,
            "normalized_text":   normalized,
            "intent_score":      raw_steps.get("intent_score", 0),
            "code_score":        raw_steps.get("code_score", 0),
            "arabic_kw_score":   raw_steps.get("arabic_score", 0),
            "keyword_score":     raw_steps.get("keyword_score", 0),
            "base_score":        base_score,
            "pipeline_decision": p1_decision,
            "transformations":   transformations,
        }

        score    = base_score
        decision = p1_decision

        # ══════════════════════════════════════════════════════════════════
        # PHASE 2 — REGEX  (on normalized text only)
        # ══════════════════════════════════════════════════════════════════
        #
        # Run Arabic + English layers on the NORMALIZED text.
        # Per-group categorization gives the dashboard meaningful labels
        # instead of raw regex strings.
        #

        # — Arabic layer ——————————————————————————————————————————————————
        ar_all_matches: List[str] = self._arabic.get_all_matches(normalized)
        ar_first: Optional[str]  = self._arabic.get_matched_pattern(normalized)
        ar_fired                 = bool(ar_first)
        ar_category              = (
            _categorize_match(ar_first, self._arabic, _ARABIC_GROUP_LABELS)
            if ar_first else "—"
        )
        ar_display_patterns = [
            _truncate_pattern(p) for p in ar_all_matches[:3]
        ]

        # — English layer —————————————————————————————————————————————————
        en_all_matches: List[str] = self._english.get_all_matches(normalized)
        en_first: Optional[str]  = self._english.get_matched_pattern(normalized)
        en_fired                 = bool(en_first)
        en_category              = (
            _categorize_match(en_first, self._english, _ENGLISH_GROUP_LABELS)
            if en_first else "—"
        )
        en_display_patterns = [
            _truncate_pattern(p) for p in en_all_matches[:3]
        ]

        # — Consolidate ———————————————————————————————————————————————————
        all_matched: List[str] = list(dict.fromkeys(ar_all_matches + en_all_matches))
        first_match: Optional[str] = ar_first or en_first
        regex_hit = bool(first_match)

        # — Score + decision bump from regex hits ——————————————————————————
        regex_score_bump = 0

        if regex_hit and decision == "SAFE":
            decision         = "FLAG"
            regex_score_bump = max(0, 85 - score)
            score            = max(score, 85)

        if ar_fired and decision != "BLOCKED":
            bump              = max(0, 130 - score)
            regex_score_bump += bump
            score             = max(score, 130)
            decision          = "BLOCKED"

        if en_fired and decision != "BLOCKED":
            bump              = max(0, 130 - score)
            regex_score_bump += bump
            score             = max(score, 130)
            decision          = "BLOCKED"

        phase2: Dict[str, Any] = {
            "ran_on": "normalized_text",
            "arabic": {
                "fired":            ar_fired,
                "category":         ar_category,
                "match_count":      len(ar_all_matches),
                "matched_patterns": ar_display_patterns,
            },
            "english": {
                "fired":            en_fired,
                "category":         en_category,
                "match_count":      len(en_all_matches),
                "matched_patterns": en_display_patterns,
            },
            "regex_score_bump":    regex_score_bump,
            "score_after_regex":   score,
            "decision_after_regex": decision,
        }

        # ══════════════════════════════════════════════════════════════════
        # PHASE 3 — MARBERT AI  (conditional)
        # ══════════════════════════════════════════════════════════════════
        #
        # Activation condition (as requested):
        #   • 80 ≤ score ≤ 120  (FLAG / borderline BLOCKED zone)
        #   • OR decision is FLAG
        #   • OR decision is BLOCKED  (AI confirms or second-opinion)
        #

        ai_prediction : Optional[int]   = None
        ai_confidence : Optional[float] = None
        ai_score_bump : int             = 0

        in_borderline = (80 <= score <= 120)
        needs_confirm = decision in {"FLAG", "BLOCKED"}
        should_use_ai = self.use_ai and (in_borderline or needs_confirm)

        if should_use_ai:
            activation_reason = (
                f"score={score} in [80,120]" if in_borderline
                else f"decision={decision} requires confirmation"
            )
        elif not self.use_ai:
            activation_reason = "AI disabled (transformers not installed)"
        else:
            activation_reason = (
                f"score={score} outside [80,120] and decision={decision} — skipped"
            )

        if should_use_ai:
            ai_prediction, ai_confidence = self._ai_predict(normalized)

            if ai_prediction == 1:
                if ai_confidence >= 0.75:
                    prev_score = score
                    score      = max(score, 130)
                    ai_score_bump = score - prev_score
                    decision   = "BLOCKED"
                    logger.info(
                        "AI → BLOCKED  conf=%.3f  score=%d  text=%r",
                        ai_confidence, score, text[:60],
                    )
                elif ai_confidence >= 0.55:
                    if decision == "SAFE":
                        decision      = "FLAG"
                        prev_score    = score
                        score         = max(score, 85)
                        ai_score_bump = score - prev_score
            else:
                # AI confident it's safe → can downgrade FLAG (not BLOCKED)
                if decision == "FLAG" and ai_confidence is not None and ai_confidence < 0.35:
                    decision = "SAFE"
                    score    = min(score, 60)
                    logger.debug("AI downgraded FLAG → SAFE  conf=%.3f", ai_confidence)

        phase3: Dict[str, Any] = {
            "activated":          should_use_ai,
            "reason":             activation_reason,
            "prediction":         ai_prediction,
            "confidence":         round(ai_confidence, 4) if ai_confidence is not None else None,
            "label":              (
                "MALICIOUS" if ai_prediction == 1
                else "SAFE"  if ai_prediction == 0
                else None
            ),
            "score_contribution": ai_score_bump,
            "decision_after_ai":  decision,
        }

        # ══════════════════════════════════════════════════════════════════
        # BLOCK-ON-FLAG  +  FINALIZE
        # ══════════════════════════════════════════════════════════════════
        if self.block_on_flag and decision == "FLAG":
            decision = "BLOCKED"

        final_score = min(score, 300)

        # ── Assemble full pipeline_steps dict (dashboard-ready) ───────────
        pipeline_steps: Dict[str, Any] = {
            "phase_1_normalization": phase1,
            "phase_2_regex":         phase2,
            "phase_3_ai":            phase3,
            "final_score":           final_score,
            "final_decision":        decision,
        }

        # ── Build human-readable reason ───────────────────────────────────
        reason = self._build_reason(
            decision, final_score,
            first_match, phase1,
            phase2, phase3,
        )

        logger.debug(
            "analyze() → %s  score=%d  ai_conf=%s",
            decision, final_score,
            f"{ai_confidence:.3f}" if ai_confidence is not None else "N/A",
        )

        return GuardResult(
            decision             = decision,
            score                = final_score,
            is_blocked           = decision == "BLOCKED",
            is_flagged           = decision in {"FLAG", "BLOCKED"},
            normalized_text      = normalized,
            matched_pattern      = first_match,
            all_matched_patterns = all_matched,
            pipeline_steps       = pipeline_steps,
            reason               = reason,
            ai_confidence        = ai_confidence,
            ai_prediction        = ai_prediction,
        )

    def batch_check(self, texts: List[str]) -> List[bool]:
        """Check a list of texts. Returns True for each safe text."""
        return [self.check(t) for t in texts]

    def batch_analyze(self, texts: List[str]) -> List[GuardResult]:
        """Analyze a list of texts. Returns one GuardResult per input."""
        return [self.analyze(t) for t in texts]

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _build_reason(
        decision : str,
        score    : int,
        match    : Optional[str],
        phase1   : Dict[str, Any],
        phase2   : Dict[str, Any],
        phase3   : Dict[str, Any],
    ) -> str:
        """
        Compose a human-readable explanation from all three phases.
        Shown in ScannerPanel and the expanded ThreatTable row.
        """
        if decision == "SAFE":
            base = f"No threats detected (score={score}/300)."
            p3   = phase3
            if p3.get("activated") and p3.get("label") == "SAFE":
                base += f" AI confirms safe (confidence={p3['confidence']:.2f})."
            return base

        parts: List[str] = [f"Decision: {decision} | Score: {score}/300."]

        # Phase 1 contributions
        if phase1.get("intent_score", 0) > 0:
            parts.append(f"[P1] Malicious code intent (+{phase1['intent_score']}).")
        if phase1.get("arabic_kw_score", 0) > 0:
            parts.append(f"[P1] Arabic injection keyword (+{phase1['arabic_kw_score']}).")
        if phase1.get("code_score", 0) > 0:
            parts.append(f"[P1] Suspicious code pattern (+{phase1['code_score']}).")
        if phase1.get("keyword_score", 0) > 0:
            parts.append(f"[P1] Dangerous keywords (+{phase1['keyword_score']}).")

        # Phase 2 contributions
        ar = phase2.get("arabic", {})
        en = phase2.get("english", {})
        if ar.get("fired"):
            parts.append(f"[P2-AR] {ar['category']} ({ar['match_count']} pattern(s) matched).")
        if en.get("fired"):
            parts.append(f"[P2-EN] {en['category']} ({en['match_count']} pattern(s) matched).")
        if match:
            short = (_truncate_pattern(match, 70))
            parts.append(f"[P2] First match: {short}")

        # Phase 3 contribution
        p3 = phase3
        if p3.get("activated") and p3.get("label"):
            conf  = p3.get("confidence") or 0.0
            label = p3["label"]
            parts.append(f"[P3-AI] {label} (confidence={conf:.2f}).")

        return " ".join(parts)

    def __repr__(self) -> str:
        ai = f"enabled on {self._device}" if self.use_ai else "disabled"
        return (
            f"ArabGuard(use_ai={ai}, "
            f"block_on_flag={self.block_on_flag}, "
            f"model={self.ai_model_name!r})"
        )