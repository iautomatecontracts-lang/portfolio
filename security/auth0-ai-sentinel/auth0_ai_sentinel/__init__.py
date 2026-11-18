"""Auth0 AI Sentinel: flags AI agents calling your Auth0 tenant."""

from __future__ import annotations

import logging

from .config import Settings


def build_sentinel(settings: Settings):
    """Wire up the Sentinel from settings, enabling Claude and Auth0 only when configured."""
    from .sentinel import Sentinel

    analyst = None
    if settings.anthropic_enabled:
        try:
            from .analyst import ClaudeAnalyst

            analyst = ClaudeAnalyst(settings.claude_model, settings.claude_effort)
        except Exception as e:  # missing credentials etc.
            logging.getLogger(__name__).warning("Claude triage disabled: %s", e)

    auth0 = None
    if settings.auth0_domain and settings.auth0_client_id and settings.auth0_client_secret:
        from .auth0 import Auth0Client

        auth0 = Auth0Client(settings.auth0_domain, settings.auth0_client_id, settings.auth0_client_secret)

    return Sentinel(settings, analyst=analyst, auth0=auth0)
