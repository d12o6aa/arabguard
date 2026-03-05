"""
config.py
=========
All application settings, loaded from environment variables / .env file.
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Server ────────────────────────────────────────────────────────────────
    host:      str  = "0.0.0.0"
    port:      int  = 8000
    debug:     bool = False
    log_level: str  = "info"
    workers:   int  = 1

    # ── CORS (comma-separated origins) ────────────────────────────────────────
    cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    # ── Model ─────────────────────────────────────────────────────────────────
    model_id:        str  = "d12o6aa/ArabGuard"
    use_ai:          bool = True
    device:          str  = "auto"   # auto | cpu | cuda | mps
    block_threshold: int  = 120
    block_on_flag:   bool = False

    # ── Rate limiting ─────────────────────────────────────────────────────────
    rate_limit_per_minute: int = 60

    # ── Analytics ─────────────────────────────────────────────────────────────
    analytics_log_file: str = "data/threat_log.jsonl"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
