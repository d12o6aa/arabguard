# ─────────────────────────────────────────────────────────────────────────────
# ArabGuard Backend — Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
#
# Build:
#   docker build -t arabguard-backend .
#
# Run (CPU):
#   docker run -p 8000:8000 --env-file .env arabguard-backend
#
# Run (GPU):
#   docker run --gpus all -p 8000:8000 --env-file .env arabguard-backend
#
# ─────────────────────────────────────────────────────────────────────────────

# ── Base image: Python 3.11 slim ──────────────────────────────────────────────
FROM python:3.11-slim AS base

# Prevents Python from writing .pyc files and enables unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# ── System dependencies ───────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ───────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install -r requirements.txt

# ── NLTK data (downloaded at build time so container starts fast) ─────────────
RUN python -c "import nltk; nltk.download('words', quiet=True)"

# ── Application source ────────────────────────────────────────────────────────
COPY . .

# ── Ensure data/ directory exists for analytics persistence ──────────────────
RUN mkdir -p data

# ── Non-root user for security ────────────────────────────────────────────────
RUN adduser --disabled-password --gecos "" appuser \
 && chown -R appuser:appuser /app
USER appuser

# ── Hugging Face cache (model weights persisted via volume) ──────────────────
# Mount: -v hf_cache:/home/appuser/.cache/huggingface
ENV HF_HOME=/home/appuser/.cache/huggingface

# ── Port ─────────────────────────────────────────────────────────────────────
EXPOSE 8000

# ── Healthcheck ───────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ── Start server ──────────────────────────────────────────────────────────────
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--log-level", "info"]
