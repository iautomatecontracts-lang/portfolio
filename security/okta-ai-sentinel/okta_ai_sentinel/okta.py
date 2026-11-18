"""Minimal Okta Management API client: System Log polling and containment actions."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import httpx

log = logging.getLogger(__name__)


class OktaClient:
    def __init__(self, org_url: str, token: str, scheme: str = "SSWS", timeout: float = 30.0):
        if not org_url or not token:
            raise ValueError("OKTA_ORG_URL and OKTA_API_TOKEN are required")
        self.org_url = org_url.rstrip("/")
        self.http = httpx.Client(
            timeout=timeout,
            headers={
                "Authorization": f"{scheme} {token}",
                "Accept": "application/json",
                "User-Agent": "okta-ai-sentinel/1.0",
            },
        )

    # -- System Log ------------------------------------------------------------

    def iter_logs(self, since: datetime | None = None, until: datetime | None = None,
                  filter_expr: str | None = None) -> Iterator[dict[str, Any]]:
        """Yield System Log events in ascending order, following pagination."""
        since = since or datetime.now(timezone.utc) - timedelta(minutes=15)
        params: dict[str, Any] = {
            "since": since.isoformat().replace("+00:00", "Z"),
            "sortOrder": "ASCENDING",
            "limit": 1000,
        }
        if until:
            params["until"] = until.isoformat().replace("+00:00", "Z")
        if filter_expr:
            params["filter"] = filter_expr

        url: str | None = f"{self.org_url}/api/v1/logs"
        while url:
            resp = self._request("GET", url, params=params)
            events = resp.json()
            yield from events
            params = None  # the "next" link already carries the query
            nxt = resp.links.get("next", {}).get("url")
            # With since-only queries Okta returns a next link forever (polling
            # mode); stop once a page comes back empty.
            url = nxt if events else None

    # -- Containment (only used when AUTO_RESPONSE is enabled) --------------------

    def clear_user_sessions(self, user_id: str) -> None:
        self._request("DELETE", f"{self.org_url}/api/v1/users/{user_id}/sessions",
                      params={"oauthTokens": "true"})

    def suspend_user(self, user_id: str) -> None:
        self._request("POST", f"{self.org_url}/api/v1/users/{user_id}/lifecycle/suspend")

    # -- internals -------------------------------------------------------------

    def _request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        for attempt in range(5):
            resp = self.http.request(method, url, **kw)
            if resp.status_code == 429:
                reset = int(resp.headers.get("X-Rate-Limit-Reset", time.time() + 5))
                wait = max(1, reset - int(time.time()))
                log.warning("Okta rate limit hit; sleeping %ss", wait)
                time.sleep(min(wait, 60))
                continue
            resp.raise_for_status()
            return resp
        resp.raise_for_status()
        return resp
