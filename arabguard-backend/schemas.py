"""
schemas.py
==========
Pydantic v2 request / response models — Full Sync Edition.

Naming convention:
  • Python fields  → snake_case  (readable backend code)
  • JSON output    → camelCase   (auto-converted via alias_generator)
  • Frontend reads camelCase keys directly — no manual mapping needed.

This single change kills the `undefined%` bug in StatCard components.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


# ─────────────────────────────────────────────────────────────────────────────
# BASE — all response models inherit camelCase serialization
# ─────────────────────────────────────────────────────────────────────────────

class _CamelModel(BaseModel):
    """Base model: snake_case Python → camelCase JSON."""
    model_config = ConfigDict(
        alias_generator  = to_camel,
        populate_by_name = True,
        from_attributes  = True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# REQUEST MODELS
# ─────────────────────────────────────────────────────────────────────────────

class PolicyOverrides(_CamelModel):
    franco:       bool = True
    national_id:  bool = True
    slang:        bool = True
    ai_layer:     bool = True
    split_letter: bool = True
    base64_hex:   bool = True
    unicode_norm: bool = True
    rot13:        bool = False


class AnalyzeRequest(_CamelModel):
    text:     str             = Field(..., min_length=1, max_length=8192)
    use_ai:   bool            = True
    debug:    bool            = False
    policies: PolicyOverrides = Field(default_factory=PolicyOverrides)


class BatchAnalyzeRequest(_CamelModel):
    texts:    List[str]       = Field(..., min_length=1, max_length=100)
    use_ai:   bool            = True
    policies: PolicyOverrides = Field(default_factory=PolicyOverrides)


class ReviewDecisionRequest(_CamelModel):
    action:      str = Field(..., pattern="^(approve|train|block)$")
    notes:       str = ""
    reviewer_id: str = "security_officer"


# ─────────────────────────────────────────────────────────────────────────────
# CORE RESPONSE
# ─────────────────────────────────────────────────────────────────────────────

class GuardResultResponse(_CamelModel):
    """
    Full analysis result — snake_case Python, camelCase JSON.

    Key mappings React will see:
      is_blocked           → isBlocked
      is_flagged           → isFlagged
      normalized_text      → normalizedText
      matched_pattern      → matchedPattern
      all_matched_patterns → allMatchedPatterns
      pipeline_steps       → pipelineSteps
      ai_confidence        → aiConfidence
      ai_prediction        → aiPrediction
      decision_source      → decisionSource
      lang_dist            → langDist
    """
    decision:             str
    score:                int
    is_blocked:           bool
    is_flagged:           bool
    normalized_text:      str
    matched_pattern:      Optional[str]            = None
    all_matched_patterns: List[str]                = Field(default_factory=list)
    pipeline_steps:       Dict[str, Any]           = Field(default_factory=dict)
    reason:               str                      = ""
    ai_confidence:        Optional[float]          = None
    ai_prediction:        Optional[int]            = None

    id:              Optional[str]                 = None
    timestamp:       datetime                      = Field(default_factory=datetime.utcnow)
    raw:             Optional[str]                 = None
    status:          Optional[str]                 = None
    risk:            Optional[str]                 = None
    vector:          Optional[str]                 = None
    decision_source: Optional[str]                 = None
    lang_dist:       Optional[Dict[str, float]]    = None


# ─────────────────────────────────────────────────────────────────────────────
# THREAT LOG
# ─────────────────────────────────────────────────────────────────────────────

class ThreatLogItem(GuardResultResponse):
    id: str


class ThreatLogsResponse(_CamelModel):
    items: List[ThreatLogItem]
    total: int
    page:  int
    pages: int


# ─────────────────────────────────────────────────────────────────────────────
# ANALYTICS  (Recharts-ready Array of Objects)
# ─────────────────────────────────────────────────────────────────────────────

class LanguageDistPoint(_CamelModel):
    """Radar chart axis: { subject: "MSA", value: 60 }"""
    subject: str
    value:   float


class AttackTypeBreakdown(_CamelModel):
    """Bar chart row: { name: "…", count: 5, color: "#…" }"""
    name:  str
    count: int
    color: str


class TimelinePoint(_CamelModel):
    """Stacked area chart slot."""
    time:    str
    blocked: int
    flagged: int
    safe:    int


class DashboardSummary(_CamelModel):
    """
    GET /analytics/summary response.

    snake → camelCase:
      total_requests   → totalRequests
      total_blocked    → totalBlocked
      total_flagged    → totalFlagged
      total_safe       → totalSafe
      threat_rate      → threatRate
      ai_accuracy      → aiAccuracy
      top_vector       → topVector
      language_dist    → languageDist   (Array of { subject, value })
      attack_breakdown → attackBreakdown
    """
    total_requests:   int
    total_blocked:    int
    total_flagged:    int
    total_safe:       int
    threat_rate:      float
    ai_accuracy:      float
    top_vector:       str

    language_dist:    List[LanguageDistPoint]
    attack_breakdown: List[AttackTypeBreakdown]
    timeline:         List[TimelinePoint]


# ─────────────────────────────────────────────────────────────────────────────
# REVIEW QUEUE
# ─────────────────────────────────────────────────────────────────────────────

class QueueItem(_CamelModel):
    """
    Queue row — all records visible, filterable by status.

    snake → camelCase:
      ai_confidence → aiConfidence
      ai_prediction → aiPrediction
    """
    id:            str
    text:          str
    normalized:    str
    score:         int
    risk:          str
    status:        str
    vector:        str
    ai_confidence: Optional[float] = None
    ai_prediction: Optional[int]   = None
    timestamp:     datetime


class QueueResponse(_CamelModel):
    items:          List[QueueItem]
    total:          int
    filter_applied: str = "ALL"


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────

class HealthResponse(_CamelModel):
    backend:    str
    model:      str
    model_id:   str
    device:     str
    ai_enabled: bool
    version:    str = "1.0.0"