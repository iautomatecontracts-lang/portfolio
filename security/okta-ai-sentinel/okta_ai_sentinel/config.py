"""Runtime configuration, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _csv(name: str) -> frozenset[str]:
    raw = os.getenv(name, "")
    return frozenset(v.strip().lower() for v in raw.split(",") if v.strip())


def _float(name: str, default: float) -> float:
    return float(os.getenv(name, default))


@dataclass(frozen=True)
class Settings:
    # --- Okta -------------------------------------------------------------
    okta_org_url: str = field(default_factory=lambda: os.getenv("OKTA_ORG_URL", "").rstrip("/"))
    # API token (SSWS) or OAuth access token for a service app with okta.logs.read
    # (and okta.users.manage only if AUTO_RESPONSE is enabled).
    okta_api_token: str = field(default_factory=lambda: os.getenv("OKTA_API_TOKEN", ""))
    okta_auth_scheme: str = field(default_factory=lambda: os.getenv("OKTA_AUTH_SCHEME", "SSWS"))
    # Shared secret Okta sends in the Authorization header of each Event Hook call.
    event_hook_secret: str = field(default_factory=lambda: os.getenv("OKTA_EVENT_HOOK_SECRET", ""))

    # --- Detection ----------------------------------------------------------
    flag_threshold: float = field(default_factory=lambda: _float("FLAG_THRESHOLD", 0.6))
    triage_threshold: float = field(default_factory=lambda: _float("TRIAGE_THRESHOLD", 0.35))
    window_seconds: int = field(default_factory=lambda: int(os.getenv("WINDOW_SECONDS", 900)))
    # Actors (Okta user id, login, or OAuth client id) that are known automation.
    allowlist: frozenset[str] = field(default_factory=lambda: _csv("ALLOWLIST"))

    # --- Claude analyst -------------------------------------------------------
    anthropic_enabled: bool = field(
        default_factory=lambda: os.getenv("CLAUDE_TRIAGE", "true").lower() == "true"
    )
    claude_model: str = field(default_factory=lambda: os.getenv("CLAUDE_MODEL", "claude-opus-5-5"))
    claude_effort: str = field(default_factory=lambda: os.getenv("CLAUDE_EFFORT", "medium"))

    # --- Alerting / response -------------------------------------------------
    slack_webhook_url: str = field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL", ""))
    # none | clear_sessions | suspend   (default: flag only, never touch accounts)
    auto_response: str = field(default_factory=lambda: os.getenv("AUTO_RESPONSE", "none").lower())
    auto_response_min_confidence: float = field(
        default_factory=lambda: _float("AUTO_RESPONSE_MIN_CONFIDENCE", 0.9)
    )


def load() -> Settings:
    return Settings()
