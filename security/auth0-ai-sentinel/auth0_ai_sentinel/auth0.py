"""Minimal Auth0 Management API client: log polling and containment actions."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import quote

import httpx

log = logging.getLogger(__name__)


class Auth0Client:
    def __init__(self, domain: str, client_id: str, client_secret: str, timeout: float = 30.0):
        if not (domain and client_id and client_secret):
            raise ValueError("AUTH0_DOMAIN, AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET are required")
        self.base = f"https://{domain}"
        self.client_id = client_id
        self.client_secret = client_secret
        self.http = httpx.Client(timeout=timeout, headers={"User-Agent": "auth0-ai-sentinel/1.0"})
        self._token: Optional[str] = None
        self._token_exp = 0.0

    # -- auth --------------------------------------------------------------------

    def _access_token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        resp = self.http.post(
            f"{self.base}/oauth/token",
            json={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "audience": f"{self.base}/api/v2/",
            },
        )
        resp.raise_for_status()
        body = resp.json()
        self._token = body["access_token"]
        self._token_exp = time.time() + int(body.get("expires_in", 3600))
        return self._token

    # -- logs ----------------------------------------------------------------------

    def latest_logs(self, count: int = 100) -> List[Dict[str, Any]]:
        """Most recent logs, oldest first. Used to seed the checkpoint on start."""
        resp = self._request("GET", "/api/v2/logs",
                             params={"per_page": min(count, 100), "sort": "date:-1"})
        return list(reversed(resp.json()))

    def logs_after(self, log_id: str, take: int = 100) -> Iterator[Dict[str, Any]]:
        """Checkpoint pagination: every log after `log_id`, oldest first."""
        while True:
            resp = self._request("GET", "/api/v2/logs", params={"from": log_id, "take": take})
            page = resp.json()
            if not page:
                return
            yield from page
            log_id = page[-1]["log_id"]
            if len(page) < take:
                return

    # -- containment (only used when AUTO_RESPONSE is enabled) ---------------------

    def revoke_sessions(self, user_id: str) -> None:
        uid = quote(user_id, safe="")
        self._request("DELETE", f"/api/v2/users/{uid}/sessions")
        self._request("DELETE", f"/api/v2/users/{uid}/refresh-tokens")

    def block_user(self, user_id: str) -> None:
        self._request("PATCH", f"/api/v2/users/{quote(user_id, safe='')}", json={"blocked": True})

    # -- internals -------------------------------------------------------------

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        resp = None
        for _ in range(5):
            headers = {"Authorization": f"Bearer {self._access_token()}"}
            resp = self.http.request(method, f"{self.base}{path}", headers=headers, **kw)
            if resp.status_code == 429:
                reset = int(resp.headers.get("x-ratelimit-reset", time.time() + 5))
                wait = max(1, reset - int(time.time()))
                log.warning("Auth0 rate limit hit; sleeping %ss", wait)
                time.sleep(min(wait, 60))
                continue
            if resp.status_code == 401:
                self._token = None  # token expired or revoked; fetch a new one
                continue
            resp.raise_for_status()
            return resp
        assert resp is not None
        resp.raise_for_status()
        return resp
