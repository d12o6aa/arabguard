"""
arabguard/core.py
=================
Main entry point for the ArabGuard SDK.

Usage
-----
    from arabguard import ArabGuard

    guard = ArabGuard()

    # Simple boolean check
    is_safe = guard.check("نص البحث")

    # Detailed result
    result = guard.analyze("نص البحث")
    print(result["decision"])   # "SAFE" | "FLAG" | "BLOCKED"
    print(result["score"])      # 0 – 300
    print(result["reason"])     # human-readable explanation
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from .pipeline        import normalize_and_detect
from .security_layers import (
    ArabicRegexSecurityLayer,
    RegexSecurityLayer,
    CombinedSecurityLayer,
)

# ── Optional AI model imports (graceful fallback) ────────────────────────────
try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
    _TRANSFORMERS_AVAILABLE = True
except ImportError:
    _TRANSFORMERS_AVAILABLE = False
    AutoTokenizer = None
    AutoModelForSequenceClassification = None
    torch = None


# ─────────────────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class GuardResult:
    """
    Full analysis result returned by :meth:`ArabGuard.analyze`.

    Attributes
    ----------
    decision : str
        One of ``"SAFE"``, ``"FLAG"``, or ``"BLOCKED"``.
    score : int
        Aggregate risk score (0 – 300).  Higher = more dangerous.
    is_blocked : bool
        Shorthand for ``decision == "BLOCKED"``.
    is_flagged : bool
        Shorthand for ``decision in {"FLAG", "BLOCKED"}``.
    normalized_text : str
        The text after full normalization / deobfuscation.
    matched_pattern : Optional[str]
        The first regex pattern that matched, or ``None``.
    all_matched_patterns : List[str]
        All patterns that matched (useful for debugging).
    pipeline_steps : Dict[str, Any]
        Intermediate scores from each pipeline stage.
    reason : str
        Human-readable explanation of the decision.
    ai_confidence : Optional[float]
        Confidence score from AI model (0.0 – 1.0), or ``None`` if AI not used.
    ai_prediction : Optional[int]
        AI model prediction (0=safe, 1=malicious), or ``None`` if AI not used.
    """
    decision            : str
    score               : int
    is_blocked          : bool
    is_flagged          : bool
    normalized_text     : str
    matched_pattern     : Optional[str]          = field(default=None)
    all_matched_patterns: List[str]              = field(default_factory=list)
    pipeline_steps      : Dict[str, Any]         = field(default_factory=dict)
    reason              : str                    = ""
    ai_confidence       : Optional[float]        = field(default=None)
    ai_prediction       : Optional[int]          = field(default=None)

    def __bool__(self) -> bool:
        """True when the text is safe (not blocked and not flagged)."""
        return not self.is_flagged

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision"            : self.decision,
            "score"               : self.score,
            "is_blocked"          : self.is_blocked,
            "is_flagged"          : self.is_flagged,
            "normalized_text"     : self.normalized_text,
            "matched_pattern"     : self.matched_pattern,
            "all_matched_patterns": self.all_matched_patterns,
            "pipeline_steps"      : self.pipeline_steps,
            "reason"              : self.reason,
            "ai_confidence"       : self.ai_confidence,
            "ai_prediction"       : self.ai_prediction,
        }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class ArabGuard:
    """
    Multi-layer Arabic/English prompt-injection and jailbreak detector.

    Layers
    ------
    1. **Normalization pipeline** – deobfuscation, encoding detection,
       Arabic normalization, intent-aware sanitization, keyword scoring.
    2. **Arabic regex layer** – Egyptian Arabic + Franko dialect patterns.
    3. **English regex layer** – Unicode attacks, DAN/jailbreak phrases,
       system-access attempts, data exfiltration, adversarial patterns.
    4. **AI deep analysis layer** – MARBERT-based classification for
       borderline cases (optional, enabled by default if transformers available).

    Parameters
    ----------
    block_on_flag : bool
        If ``True``, "FLAG" results are treated as "BLOCKED".
        Default: ``False``.
    custom_score_threshold : Optional[int]
        Override the default BLOCKED threshold (120).
        If provided, any score ≥ this value → BLOCKED.
    use_ai : bool
        Enable AI model for deep analysis. Default: ``True`` if transformers
        is installed, ``False`` otherwise. The AI model activates for borderline
        cases (score 60-119) when regex/pipeline results are uncertain.
    ai_model_name : str
        Hugging Face model name. Default: ``"d12o6aa/ArabGuard"``.
    device : Optional[str]
        Device for AI model ("cpu", "cuda", "mps"). Default: auto-detect.
    """

    def __init__(
        self,
        block_on_flag: bool = False,
        custom_score_threshold: Optional[int] = None,
        use_ai: bool = True,
        ai_model_name: str = "d12o6aa/ArabGuard",
        device: Optional[str] = None,
    ):
        self.block_on_flag          = block_on_flag
        self.custom_score_threshold = custom_score_threshold
        self.use_ai                 = use_ai and _TRANSFORMERS_AVAILABLE
        self.ai_model_name          = ai_model_name

        # Instantiate regex layers
        self._arabic   = ArabicRegexSecurityLayer()
        self._english  = RegexSecurityLayer()
        self._combined = CombinedSecurityLayer()

        # ── AI Model Setup ────────────────────────────────────────────────
        self._tokenizer = None
        self._model     = None
        self._device    = None

        if self.use_ai:
            if not _TRANSFORMERS_AVAILABLE:
                warnings.warn(
                    "transformers/torch not available. AI layer disabled. "
                    "Install with: pip install transformers torch scipy",
                    RuntimeWarning,
                )
                self.use_ai = False
            else:
                self._load_ai_model(device)

    def _load_ai_model(self, device: Optional[str] = None):
        """Load the MARBERT-based AI model from Hugging Face."""
        try:
            # Auto-detect device
            if device is None:
                if torch.cuda.is_available():
                    device = "cuda"
                elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
                    device = "mps"
                else:
                    device = "cpu"
            self._device = device

            # Load tokenizer and model
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.ai_model_name,
                use_fast=True,
            )
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.ai_model_name,
            )
            self._model.to(self._device)
            self._model.eval()

        except Exception as e:
            warnings.warn(
                f"Failed to load AI model '{self.ai_model_name}': {e}. "
                "AI layer disabled.",
                RuntimeWarning,
            )
            self.use_ai = False
            self._tokenizer = None
            self._model     = None
            self._device    = None

    def _ai_predict(self, text: str) -> tuple[int, float]:
        """
        Run AI model inference.

        Returns
        -------
        (prediction, confidence)
            prediction : int (0=safe, 1=malicious)
            confidence : float (0.0 – 1.0)
        """
        if not self.use_ai or self._model is None:
            return 0, 0.0

        try:
            # Tokenize
            inputs = self._tokenizer(
                text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True,
            )
            inputs = {k: v.to(self._device) for k, v in inputs.items()}

            # Inference
            with torch.no_grad():
                outputs = self._model(**inputs)
                logits  = outputs.logits
                probs   = torch.softmax(logits, dim=-1)

            # Extract prediction
            prediction = torch.argmax(probs, dim=-1).item()
            confidence = probs[0, prediction].item()

            return int(prediction), float(confidence)

        except Exception as e:
            warnings.warn(
                f"AI inference failed: {e}. Returning safe prediction.",
                RuntimeWarning,
            )
            return 0, 0.0

    # ── Public API ────────────────────────────────────────────────────────

    def check(self, text: str) -> bool:
        """
        Fast boolean safety check.

        Returns
        -------
        bool
            ``True``  → text is **safe** (not blocked / flagged).
            ``False`` → text is **blocked** or **flagged**.
        """
        result = self.analyze(text)
        return not result.is_flagged

    def analyze(self, text: str) -> GuardResult:
        """
        Full multi-layer analysis.

        Returns
        -------
        GuardResult
            Detailed result including decision, score, matched patterns,
            pipeline diagnostics, and AI prediction (if enabled).
        """
        if not isinstance(text, str):
            text = str(text)

        # ── Layer 1: normalization pipeline ──────────────────────────────
        normalized, score, pipeline_decision, steps = normalize_and_detect(
            text, debug=True
        )

        # ── Apply custom threshold override ──────────────────────────────
        if self.custom_score_threshold is not None:
            if score >= self.custom_score_threshold:
                pipeline_decision = "BLOCKED"
            elif pipeline_decision == "BLOCKED":
                pipeline_decision = "FLAG"

        # ── Layer 2: Arabic regex layer ───────────────────────────────────
        arabic_match = self._arabic.get_matched_pattern(text)
        arabic_all   = self._arabic.get_all_matches(text)

        # Also run Arabic layer on the *normalized* text for evasion attempts
        arabic_norm_match = self._arabic.get_matched_pattern(normalized)
        arabic_norm_all   = self._arabic.get_all_matches(normalized)

        # ── Layer 3: English regex layer ──────────────────────────────────
        english_match = self._english.get_matched_pattern(text)
        english_all   = self._english.get_all_matches(text)

        english_norm_match = self._english.get_matched_pattern(normalized)
        english_norm_all   = self._english.get_all_matches(normalized)

        # ── Consolidate all matched patterns ──────────────────────────────
        all_matched: List[str] = list(
            dict.fromkeys(
                arabic_all + arabic_norm_all + english_all + english_norm_all
            )
        )
        first_match: Optional[str] = (
            arabic_match or arabic_norm_match or english_match or english_norm_match
        )

        # ── Upgrade decision if regex layers fired ────────────────────────
        regex_hit = bool(first_match)
        if regex_hit and pipeline_decision == "SAFE":
            pipeline_decision = "FLAG"
            score = max(score, 85)          # ensure score reflects FLAG level
        if (arabic_match or arabic_norm_match) and pipeline_decision != "BLOCKED":
            pipeline_decision = "BLOCKED"
            score = max(score, 130)
        if (english_match or english_norm_match) and pipeline_decision != "BLOCKED":
            pipeline_decision = "BLOCKED"
            score = max(score, 130)

        # ── Layer 4: AI Deep Analysis (for borderline cases) ──────────────
        ai_prediction: Optional[int]   = None
        ai_confidence: Optional[float] = None

        # Activate AI for borderline cases:
        # - Score 60-119 (between SAFE and BLOCKED)
        # - OR decision is FLAG
        # - OR no regex match but score > 40
        should_use_ai = (
            self.use_ai
            and (
                (60 <= score < 120)
                or (pipeline_decision == "FLAG")
                or (not regex_hit and score > 40)
            )
        )

        if should_use_ai:
            ai_prediction, ai_confidence = self._ai_predict(text)

            # If AI predicts malicious (1) with high confidence
            if ai_prediction == 1:
                if ai_confidence >= 0.75:
                    # High confidence → BLOCKED
                    pipeline_decision = "BLOCKED"
                    score = max(score, 130)
                elif ai_confidence >= 0.55:
                    # Medium confidence → FLAG
                    if pipeline_decision == "SAFE":
                        pipeline_decision = "FLAG"
                        score = max(score, 85)

        # ── Apply block_on_flag ───────────────────────────────────────────
        if self.block_on_flag and pipeline_decision == "FLAG":
            pipeline_decision = "BLOCKED"

        # ── Build human-readable reason ───────────────────────────────────
        reason = self._build_reason(
            pipeline_decision,
            score,
            first_match,
            steps,
            ai_prediction,
            ai_confidence,
        )

        return GuardResult(
            decision             = pipeline_decision,
            score                = min(score, 300),
            is_blocked           = pipeline_decision == "BLOCKED",
            is_flagged           = pipeline_decision in {"FLAG", "BLOCKED"},
            normalized_text      = normalized,
            matched_pattern      = first_match,
            all_matched_patterns = all_matched,
            pipeline_steps       = steps,
            reason               = reason,
            ai_confidence        = ai_confidence,
            ai_prediction        = ai_prediction,
        )

    def batch_check(self, texts: List[str]) -> List[bool]:
        """
        Check a list of texts.  Returns a list of booleans (True = safe).
        """
        return [self.check(t) for t in texts]

    def batch_analyze(self, texts: List[str]) -> List[GuardResult]:
        """
        Analyze a list of texts.  Returns a list of :class:`GuardResult`.
        """
        return [self.analyze(t) for t in texts]

    # ── Internal helpers ──────────────────────────────────────────────────

    @staticmethod
    def _build_reason(
        decision    : str,
        score       : int,
        match       : Optional[str],
        steps       : Dict[str, Any],
        ai_pred     : Optional[int] = None,
        ai_conf     : Optional[float] = None,
    ) -> str:
        if decision == "SAFE":
            base = f"No threats detected (score={score})."
            if ai_pred == 0 and ai_conf is not None:
                base += f" AI confirms safe (confidence={ai_conf:.2f})."
            return base

        parts: List[str] = [f"Decision: {decision} | Score: {score}/300."]

        if steps.get("intent_score", 0) > 0:
            parts.append(f"Malicious code intent detected (+{steps['intent_score']}).")
        if steps.get("arabic_score", 0) > 0:
            parts.append(f"Arabic injection keyword detected (+{steps['arabic_score']}).")
        if steps.get("code_score", 0) > 0:
            parts.append(f"Suspicious code pattern detected (+{steps['code_score']}).")
        if steps.get("keyword_score", 0) > 0:
            parts.append(f"Dangerous keywords found (+{steps['keyword_score']}).")
        if match:
            # Truncate long pattern in reason for readability
            short = (match[:80] + "…") if len(match) > 80 else match
            parts.append(f"Matched regex: {short}")

        # Add AI layer info
        if ai_pred is not None and ai_conf is not None:
            if ai_pred == 1:
                parts.append(
                    f"AI Deep Analysis: MALICIOUS (confidence={ai_conf:.2f})."
                )
            else:
                parts.append(
                    f"AI Deep Analysis: safe (confidence={ai_conf:.2f})."
                )

        return " ".join(parts)

    def __repr__(self) -> str:
        ai_status = "enabled" if self.use_ai else "disabled"
        return (
            f"ArabGuard("
            f"block_on_flag={self.block_on_flag}, "
            f"custom_score_threshold={self.custom_score_threshold}, "
            f"ai_layer={ai_status})"
        )
