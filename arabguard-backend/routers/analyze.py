"""
routers/analyze.py
==================
POST /analyze        — single text analysis (main endpoint)
POST /analyze/batch  — batch analysis (up to 100 texts)

These are the primary endpoints consumed by:
  - src/services/api.js → analyzeText()
  - src/hooks/useGuard.js → scan()
  - src/components/dashboard/ScannerPanel.jsx
"""
from __future__ import annotations

import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from guard_engine import GuardEngine
from schemas import (
    AnalyzeRequest,
    BatchAnalyzeRequest,
    GuardResultResponse,
)

logger = logging.getLogger("arabguard.analyze")
router = APIRouter(prefix="/analyze", tags=["Analysis"])


def _get_engine(request: Request) -> GuardEngine:
    """Dependency: retrieve the GuardEngine singleton from app state."""
    engine: GuardEngine = request.app.state.engine
    if not engine or not engine.model_ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ArabGuard model is not loaded yet. Please retry in a moment.",
        )
    return engine


# ─────────────────────────────────────────────────────────────────────────────
# POST /analyze
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=GuardResultResponse,
    summary="Analyze a single text for prompt injection",
    description="""
Runs the full 4-layer ArabGuard pipeline on the provided text:

1. **Normalization pipeline** — Unicode, HTML, Base64/Hex, ROT-13, confusables, split-letters
2. **Arabic regex layer**     — Egyptian Arabic + Franco-Arabic patterns
3. **English regex layer**    — DAN / bypass / exfiltration patterns
4. **MARBERT AI layer**       — activates for borderline scores (60–119)

Returns a `GuardResultResponse` that exactly matches what `api.js → analyzeText()` expects.
""",
)
async def analyze_text(
    body: AnalyzeRequest,
    engine: GuardEngine = Depends(_get_engine),
) -> GuardResultResponse:
    """
    Main analysis endpoint.

    Request body (sent by api.js):
    ```json
    {
      "text":   "user input text",
      "use_ai": true,
      "debug":  false,
      "policies": { "franco": true, "national_id": true, ... }
    }
    ```

    Response — fields consumed by the React dashboard:
    - `decision`         → StatusBadge in ThreatTable
    - `score`            → ScoreBadge
    - `risk`             → RiskBadge
    - `vector`           → Attack vector label
    - `ai_confidence`    → AiConfidenceBadge
    - `pipeline_steps`   → Expanded row breakdown
    - `normalized_text`  → Shown in expanded row
    - `reason`           → Human-readable in ScannerPanel
    """
    try:
        result = engine.analyze(body.text, use_ai_override=body.use_ai)
        return GuardResultResponse(**result)
    except Exception as e:
        logger.exception("Analysis failed for input: %r", body.text[:100])
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis error: {str(e)}",
        )


# ─────────────────────────────────────────────────────────────────────────────
# POST /analyze/batch
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/batch",
    response_model=List[GuardResultResponse],
    summary="Batch analyze up to 100 texts",
)
async def analyze_batch(
    body: BatchAnalyzeRequest,
    engine: GuardEngine = Depends(_get_engine),
) -> List[GuardResultResponse]:
    """
    Batch endpoint used by `api.js → analyzeTextBatch()`.
    Returns one GuardResultResponse per input text, in order.
    """
    if len(body.texts) > 100:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Maximum batch size is 100 texts.",
        )
    try:
        results = engine.analyze_batch(body.texts)
        return [GuardResultResponse(**r) for r in results]
    except Exception as e:
        logger.exception("Batch analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch analysis error: {str(e)}",
        )
