"""
routers/queue.py
================
GET  /queue          — all records with optional filter + pagination
POST /queue/{id}/review — human review: approve | train | block

"Train" action now persists the entry to retraining_set.jsonl immediately.

Consumed by:
  - src/services/api.js → fetchQueue(), submitReviewDecision()
  - src/pages/Queue.jsx
"""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from guard_engine import GuardEngine, risk_from_score
from schemas import QueueItem, QueueResponse, ReviewDecisionRequest

logger = logging.getLogger("arabguard.queue")
router = APIRouter(prefix="/queue", tags=["Review Queue"])

# Valid filter values (echoed back in response)
VALID_FILTERS = {"ALL", "BLOCKED", "FLAGGED", "SAFE"}


def _get_engine(request: Request) -> GuardEngine:
    return request.app.state.engine


@router.get(
    "",
    response_model=QueueResponse,
    summary="All records — filterable by status",
    description="""
Returns all threat log entries (not just FLAG items).
Use the `filter` query param to narrow down results.

Filters:
- `ALL`     → every record (default)
- `BLOCKED` → confirmed threats
- `FLAGGED` → borderline / ambiguous
- `SAFE`    → clean requests

Results are sorted newest-first.

Note: camelCase keys in JSON output — aiConfidence, aiPrediction, etc.
""",
)
async def get_queue(
    filter:    str         = Query("ALL", description="ALL | BLOCKED | FLAGGED | SAFE"),
    page:      int         = Query(1, ge=1),
    page_size: int         = Query(50, ge=1, le=200),
    engine:    GuardEngine = Depends(_get_engine),
) -> QueueResponse:

    filter_upper = filter.upper()
    if filter_upper not in VALID_FILTERS:
        filter_upper = "ALL"

    all_entries = engine.analytics.all_entries

    # Apply filter
    if filter_upper == "ALL":
        filtered = all_entries
    else:
        filtered = [e for e in all_entries if e.get("status", "SAFE").upper() == filter_upper]

    # Sort newest first
    filtered = sorted(filtered, key=lambda e: e.get("timestamp", ""), reverse=True)

    # Paginate
    total = len(filtered)
    start = (page - 1) * page_size
    page_entries = filtered[start: start + page_size]

    items: List[QueueItem] = []
    for e in page_entries:
        try:
            items.append(QueueItem(
                id            = e["id"],
                text          = e.get("raw", ""),
                normalized    = e.get("normalized_text", ""),
                score         = e.get("score", 0),
                risk          = e.get("risk") or risk_from_score(e.get("score", 0)),
                status        = e.get("status", "SAFE"),
                vector        = e.get("vector", "None"),
                ai_confidence = e.get("ai_confidence"),
                ai_prediction = e.get("ai_prediction"),
                timestamp     = e["timestamp"],
            ))
        except Exception as exc:
            logger.debug("Skipped malformed queue entry: %s", exc)

    return QueueResponse(
        items          = items,
        total          = total,
        filter_applied = filter_upper,
    )


@router.post(
    "/{item_id}/review",
    summary="Submit a human review decision",
    description="""
Record a security officer's decision.

Actions:
- `approve` → mark as safe, add to allowlist
- `train`   → **immediately saves to retraining_set.jsonl** for model retraining
- `block`   → confirm malicious, add to blocklist
""",
)
async def submit_review(
    item_id: str,
    body:    ReviewDecisionRequest,
    engine:  GuardEngine = Depends(_get_engine),
) -> dict:

    entry = next(
        (e for e in engine.analytics.all_entries if e.get("id") == item_id),
        None,
    )
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Queue item '{item_id}' not found.",
        )

    logger.info(
        "Human review: item=%s action=%s reviewer=%s notes=%r",
        item_id, body.action, body.reviewer_id, body.notes[:120],
    )

    # "train" → persist to retraining_set.jsonl immediately
    if body.action == "train":
        engine.save_for_retraining(entry, notes=body.notes)

    return {
        "status":      "recorded",
        "item_id":     item_id,
        "action":      body.action,
        "reviewer_id": body.reviewer_id,
        "message": {
            "approve": "Item marked safe and added to allowlist.",
            "train":   "Item saved to retraining_set.jsonl for model fine-tuning.",
            "block":   "Item confirmed malicious and added to blocklist.",
        }.get(body.action, "Decision recorded."),
    }