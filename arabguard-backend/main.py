"""
main.py
=======
ArabGuard FastAPI Backend — Entry Point
=======================================

Endpoints
---------
POST   /analyze                      ← Main analysis (ScannerPanel + ThreatTable)
POST   /analyze/batch                ← Batch analysis
GET    /logs/threats                 ← Paginated threat log
GET    /logs/threats/{id}            ← Single threat detail
GET    /analytics/summary            ← Dashboard stats + chart data
GET    /analytics/language-distribution ← Radar chart data
GET    /queue/ambiguous              ← Human-in-the-loop review queue
POST   /queue/{id}/review            ← Submit review decision
GET    /settings/policies            ← Current guardrail state
PATCH  /settings/policies/{key}      ← Toggle a single policy
PUT    /settings/policies            ← Replace all policies
GET    /health                       ← Health check
GET    /                             ← API info

Quick start
-----------
    # Development (auto-reload)
    uvicorn main:app --reload --port 8000

    # Production
    uvicorn main:app --host 0.0.0.0 --port 8000 --workers 2

    # Or via python
    python main.py
"""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import get_settings
from guard_engine import GuardEngine
from schemas import HealthResponse
from routers import analyze, analytics, logs, queue
from routers import settings as settings_router

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("arabguard.main")

cfg = get_settings()


# ─────────────────────────────────────────────────────────────────────────────
# LIFESPAN  — model loads ONCE on startup, cleaned up on shutdown
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.

    Startup:
      1. Create data/ directory for analytics persistence
      2. Instantiate GuardEngine and warm the MARBERT model
         (first run downloads ~300 MB from Hugging Face Hub)
      3. Attach engine to app.state so routers can access it

    Shutdown:
      - Cleanup handled implicitly (model stays in RAM until process exits)
    """
    logger.info("══════════════════════════════════════════")
    logger.info("  ArabGuard Backend  v1.0.0  — starting")
    logger.info("══════════════════════════════════════════")
    logger.info("  Model  : %s", cfg.model_id)
    logger.info("  AI     : %s", "enabled" if cfg.use_ai else "disabled (regex-only)")
    logger.info("  Device : %s (auto-detect)", cfg.device)
    logger.info("  CORS   : %s", cfg.cors_origins_list)

    # Ensure data directory exists for analytics persistence
    Path("data").mkdir(exist_ok=True)

    # Instantiate and warm the engine
    engine = GuardEngine(cfg)
    try:
        engine.load()
        logger.info("  ✓ Model loaded and ready")
    except Exception as exc:
        # Don't crash — /analyze will return HTTP 503 until model is ready
        logger.error("  ✗ Model failed to load: %s", exc)
        logger.warning("  Running in degraded mode (regex-only, no AI)")

    app.state.engine = engine
    logger.info("  ✓ Server accepting requests on %s:%s", cfg.host, cfg.port)
    logger.info("══════════════════════════════════════════")

    yield   # ← server is running

    logger.info("ArabGuard Backend shutting down — bye!")


# ─────────────────────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "ArabGuard API",
    description = (
        "## ArabGuard — Multi-layer Arabic/English Prompt-Injection Detection\n\n"
        "**Model**: [`d12o6aa/ArabGuard`](https://huggingface.co/d12o6aa/ArabGuard) "
        "(MARBERT · F1=0.97 · Precision=0.96 · Recall=0.98)\n\n"
        "**Specialisation**: Egyptian Arabic, Franco-Arabic (Franko), MSA\n\n"
        "**Frontend**: React dashboard (`arabguard-dashboard`)"
    ),
    version     = "1.0.0",
    lifespan    = lifespan,
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    contact     = {"name": "ArabGuard", "url": "https://github.com/arabguard/arabguard"},
    license_info= {"name": "MIT"},
)


# ─────────────────────────────────────────────────────────────────────────────
# MIDDLEWARE
# ─────────────────────────────────────────────────────────────────────────────

# ── 1) CORS — allow the React dashboard origin ────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins     = cfg.cors_origins_list,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
    expose_headers    = ["X-Process-Time", "X-Request-ID"],
)


# ── 2) Request timing header ─────────────────────────────────────────────────
@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    start    = time.perf_counter()
    response = await call_next(request)
    elapsed  = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time"] = f"{elapsed:.1f}ms"
    if request.url.path not in ("/health", "/"):
        logger.info("%-6s %-40s  %s  %.0fms",
                    request.method, request.url.path,
                    response.status_code, elapsed)
    return response


# ── 3) Global exception handler ───────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error.",
            "type":   type(exc).__name__,
            "path":   request.url.path,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# ROUTERS
# ─────────────────────────────────────────────────────────────────────────────

app.include_router(analyze.router)
app.include_router(analytics.router)
app.include_router(logs.router)
app.include_router(queue.router)
app.include_router(settings_router.router)


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH  &  ROOT
# ─────────────────────────────────────────────────────────────────────────────

@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Backend and model health check",
    description="Polled by `api.js → checkHealth()` every 30 s and by the Sidebar status pill.",
)
async def health_check(request: Request) -> HealthResponse:
    engine: GuardEngine = getattr(request.app.state, "engine", None)
    guard  = engine.guard if engine else None
    return HealthResponse(
        backend    = "online",
        model      = "loaded" if (engine and engine.model_ready) else "not_loaded",
        model_id   = cfg.model_id,
        device     = getattr(guard, "_device", "N/A") if guard else "N/A",
        ai_enabled = bool(guard and guard.use_ai),
        version    = "1.0.0",
    )


@app.get("/", tags=["Health"], include_in_schema=False)
async def root():
    return {
        "name":    "ArabGuard API",
        "version": "1.0.0",
        "docs":    "/docs",
        "model":   cfg.model_id,
        "status":  "online",
    }


# ─────────────────────────────────────────────────────────────────────────────
# DIRECT RUN  (python main.py)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host      = cfg.host,
        port      = cfg.port,
        reload    = cfg.debug,
        workers   = cfg.workers if not cfg.debug else 1,
        log_level = cfg.log_level,
    )
