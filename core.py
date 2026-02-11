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

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from .pipeline        import normalize_and_detect
from .security_layers import (
    ArabicRegexSecurityLayer,
    RegexSecurityLayer,
    CombinedSecurityLayer,
)


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

    Parameters
    ----------
    block_on_flag : bool
        If ``True``, "FLAG" results are treated as "BLOCKED".
        Default: ``False``.
    custom_score_threshold : Optional[int]
        Override the default BLOCKED threshold (120).
        If provided, any score ≥ this value → BLOCKED.
    """

    def __init__(
        self,
        block_on_flag: bool = False,
        custom_score_threshold: Optional[int] = None,
    ):
        self.block_on_flag          = block_on_flag
        self.custom_score_threshold = custom_score_threshold

        # Instantiate all three layers
        self._arabic   = ArabicRegexSecurityLayer()
        self._english  = RegexSecurityLayer()
        self._combined = CombinedSecurityLayer()

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
            Detailed result including decision, score, matched patterns
            and pipeline diagnostics.
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

        # ── Apply block_on_flag ───────────────────────────────────────────
        if self.block_on_flag and pipeline_decision == "FLAG":
            pipeline_decision = "BLOCKED"

        # ── Build human-readable reason ───────────────────────────────────
        reason = self._build_reason(
            pipeline_decision, score, first_match, steps
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
    ) -> str:
        if decision == "SAFE":
            return f"No threats detected (score={score})."

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

        return " ".join(parts)

    def __repr__(self) -> str:
        return (
            f"ArabGuard("
            f"block_on_flag={self.block_on_flag}, "
            f"custom_score_threshold={self.custom_score_threshold})"
        )
