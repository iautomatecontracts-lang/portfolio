"""Runtime configuration, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _csv(name: str) -> frozenset:
    raw = os.getenv(name, "")
    return frozenset(v.strip().lower() for v in raw.split(",") if v.strip())


def _float(name: str, default: float) -> float:
    return float(os.getenv(name, default))


@dataclass(frozen=True)
class Settings:
    # --- Auth0 ------------------------------------------------------------
    # Tenant domain, e.g. your-tenant.us.auth0.com (no scheme).
    auth0_domain: str = field(default_factory=lambda: os.getenv("AUTH0_DOMAIN", "").replace("https://", "").rstrip("/"))
    # Machine-to-machine app authorized for the Management API with read:logs
    # (plus update:users / delete:sessions / delete:refresh_tokens only if AUTO_RESPONSE is on).
    auth0_client_id: str = field(default_factory=lambda: os.getenv("AUTH0_CLIENT_ID", ""))
    auth0_client_secret: str = field(default_factory=lambda: os.getenv("AUTH0_CLIENT_SECRET", ""))
    # Value Auth0 sends in the Authorization header of each Log Stream (custom webhook) call.
    log_stream_secret: str = field(default_factory=lambda: os.getenv("AUTH0_LOG_STREAM_SECRET", ""))

    # --- Detection ----------------------------------------------------------
    flag_threshold: float = field(default_factory=lambda: _float("FLAG_THRESHOLD", 0.6))
    triage_threshold: float = field(default_factory=lambda: _float("TRIAGE_THRESHOLD", 0.35))
    window_seconds: int = field(default_factory=lambda: int(os.getenv("WINDOW_SECONDS", 900)))
    # Sanctioned automation: Auth0 user_id, user_name/email, or client_id.
    allowlist: frozenset = field(default_factory=lambda: _csv("ALLOWLIST"))

    # --- Claude analyst -------------------------------------------------------
    anthropic_enabled: bool = field(
        default_factory=lambda: os.getenv("CLAUDE_TRIAGE", "true").lower() == "true"
    )
    claude_model: str = field(default_factory=lambda: os.getenv("CLAUDE_MODEL", "claude-opus-5-5"))
    claude_effort: str = field(default_factory=lambda: os.getenv("CLAUDE_EFFORT", "medium"))

    # --- Alerting / response -------------------------------------------------
    slack_webhook_url: str = field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL", ""))
    # none | revoke_sessions | block   (default: flag only, never touch accounts)
    auto_response: str = field(default_factory=lambda: os.getenv("AUTO_RESPONSE", "none").lower())
    auto_response_min_confidence: float = field(
        default_factory=lambda: _float("AUTO_RESPONSE_MIN_CONFIDENCE", 0.9)
    )


def load() -> Settings:
    return Settings()
