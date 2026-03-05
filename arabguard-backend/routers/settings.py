"""
routers/settings.py
===================
GET  /settings/policies          — current policy state
PATCH /settings/policies/{key}   — toggle a single policy
PUT   /settings/policies         — replace all policies

Consumed by:
  - src/services/api.js → fetchPolicies(), updatePolicy(), updateAllPolicies()
  - src/hooks/usePolicies.js
  - src/components/dashboard/GuardrailToggles.jsx
"""
from __future__ import annotations

import logging
from typing import Dict

from fastapi import APIRouter, Request

from schemas import PolicyOverrides

logger = logging.getLogger("arabguard.settings")
router = APIRouter(prefix="/settings", tags=["Settings"])

# In-memory policy state (single process).
# In production, store in Redis or a DB.
_current_policies = PolicyOverrides()


@router.get(
    "/policies",
    response_model=PolicyOverrides,
    summary="Get current policy configuration",
)
async def get_policies() -> PolicyOverrides:
    return _current_policies


@router.patch(
    "/policies/{policy_key}",
    summary="Toggle a single policy on or off",
)
async def update_single_policy(policy_key: str, body: dict) -> dict:
    global _current_policies
    enabled = body.get("enabled")
    if enabled is None or not isinstance(enabled, bool):
        from fastapi import HTTPException, status
        raise HTTPException(status_code=422, detail="'enabled' (bool) required in body.")

    if not hasattr(_current_policies, policy_key):
        from fastapi import HTTPException, status
        raise HTTPException(status_code=404, detail=f"Unknown policy key: '{policy_key}'")

    # Rebuild with the updated field
    data = _current_policies.model_dump()
    data[policy_key] = enabled
    _current_policies = PolicyOverrides(**data)
    logger.info("Policy updated: %s → %s", policy_key, enabled)
    return {"policy": policy_key, "enabled": enabled}


@router.put(
    "/policies",
    response_model=PolicyOverrides,
    summary="Replace all policies at once",
)
async def update_all_policies(body: Dict[str, bool]) -> PolicyOverrides:
    global _current_policies
    current = _current_policies.model_dump()
    current.update({k: v for k, v in body.items() if k in current})
    _current_policies = PolicyOverrides(**current)
    logger.info("All policies updated: %s", current)
    return _current_policies
