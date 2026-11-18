"""HTTP endpoint for Okta Event Hooks (real-time push from Okta).

Okta calls GET once with X-Okta-Verification-Challenge to verify the endpoint,
then POSTs batches of System Log events. Okta waits ~3s for a response, so
events are acknowledged immediately and analyzed in the background.
"""

from __future__ import annotations

import hmac
import logging
import threading
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

from . import build_sentinel
from .config import load

log = logging.getLogger(__name__)

settings = load()
sentinel = build_sentinel(settings)
_lock = threading.Lock()  # detector state is not thread-safe

app = FastAPI(title="Okta AI Sentinel")


def _check_auth(authorization: Optional[str]) -> None:
    if not settings.event_hook_secret:
        raise HTTPException(503, "OKTA_EVENT_HOOK_SECRET is not configured")
    if not authorization or not hmac.compare_digest(authorization, settings.event_hook_secret):
        raise HTTPException(401, "bad hook credentials")


@app.get("/okta/events")
def verify(x_okta_verification_challenge: str = Header(...),
           authorization: Optional[str] = Header(None)) -> dict[str, str]:
    _check_auth(authorization)
    return {"verification": x_okta_verification_challenge}


def _process(events: list[dict[str, Any]]) -> None:
    with _lock:
        for event in events:
            try:
                sentinel.process(event)
            except Exception:
                log.exception("Failed processing event %s", event.get("uuid"))


@app.post("/okta/events", status_code=200)
async def receive(request: Request, background: BackgroundTasks,
                  authorization: Optional[str] = Header(None)) -> dict[str, int]:
    _check_auth(authorization)
    body = await request.json()
    events = (body.get("data") or {}).get("events") or []
    background.add_task(_process, events)
    return {"accepted": len(events)}


@app.get("/healthz")
def health() -> dict[str, str]:
    return {"status": "ok"}
