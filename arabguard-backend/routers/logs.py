"""
routers/logs.py
===============
GET /logs/threats        — paginated threat log (ThreatTable.jsx)
GET /logs/threats/{id}   — single threat detail
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from guard_engine import GuardEngine
from schemas import ThreatLogItem, ThreatLogsResponse

logger = logging.getLogger("arabguard.logs")
router = APIRouter(prefix="/logs", tags=["Logs"])


def _get_engine(request: Request) -> GuardEngine:
    return request.app.state.engine


@router.get(
    "/threats",
    response_model=ThreatLogsResponse,
    summary="Paginated threat log",
    description="Returns the rolling threat log consumed by ThreatTable.jsx via `api.js → fetchThreatLogs()`.",
)
async def get_threats(
    page:      int            = Query(1, ge=1),
    page_size: int            = Query(50, ge=1, le=200),
    filter:    Optional[str]  = Query(None, description="ALL | BLOCKED | FLAGGED | SAFE"),
    date_from: Optional[str]  = Query(None),
    date_to:   Optional[str]  = Query(None),
    engine:    GuardEngine    = Depends(_get_engine),
) -> ThreatLogsResponse:

    entries = engine.analytics.all_entries

    # ── Apply status filter ──────────────────────────────────────────────────
    if filter and filter.upper() != "ALL":
        entries = [e for e in entries if e.get("status", "").upper() == filter.upper()]

    # ── Apply date range ─────────────────────────────────────────────────────
    if date_from:
        entries = [e for e in entries if e.get("timestamp", "") >= date_from]
    if date_to:
        entries = [e for e in entries if e.get("timestamp", "") <= date_to]

    # ── Sort newest first ────────────────────────────────────────────────────
    entries = sorted(entries, key=lambda e: e.get("timestamp", ""), reverse=True)

    total = len(entries)
    pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    page_items = entries[start : start + page_size]

    items = []
    for e in page_items:
        try:
            items.append(ThreatLogItem(**e))
        except Exception:
            pass   # skip malformed entries

    return ThreatLogsResponse(items=items, total=total, page=page, pages=pages)


@router.get(
    "/threats/{threat_id}",
    response_model=ThreatLogItem,
    summary="Get a single threat log entry by ID",
)
async def get_threat_by_id(
    threat_id: str,
    engine: GuardEngine = Depends(_get_engine),
) -> ThreatLogItem:
    for entry in engine.analytics.all_entries:
        if entry.get("id") == threat_id:
            return ThreatLogItem(**entry)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Threat log entry '{threat_id}' not found.",
    )
