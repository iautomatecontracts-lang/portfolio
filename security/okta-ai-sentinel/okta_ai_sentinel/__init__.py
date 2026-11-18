"""Okta AI Sentinel: flags AI agents calling your Okta org."""

from __future__ import annotations

import logging

from .config import Settings


def build_sentinel(settings: Settings):
    """Wire up the Sentinel from settings, enabling Claude and Okta only when configured."""
    from .sentinel import Sentinel

    analyst = None
    if settings.anthropic_enabled:
        try:
            from .analyst import ClaudeAnalyst

            analyst = ClaudeAnalyst(settings.claude_model, settings.claude_effort)
        except Exception as e:  # missing credentials etc.
            logging.getLogger(__name__).warning("Claude triage disabled: %s", e)

    okta = None
    if settings.okta_org_url and settings.okta_api_token:
        from .okta import OktaClient

        okta = OktaClient(settings.okta_org_url, settings.okta_api_token, settings.okta_auth_scheme)

    return Sentinel(settings, analyst=analyst, okta=okta)
