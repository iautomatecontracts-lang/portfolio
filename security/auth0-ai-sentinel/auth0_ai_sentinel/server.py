"""HTTP endpoint for an Auth0 Log Stream (custom webhook).

Auth0 POSTs batches of tenant logs as a JSON array, JSON lines, or a single
JSON object, each item shaped {"log_id": ..., "data": {...}}. Batches are
acknowledged at once and analyzed in the background.
"""

from __future__ import annotations

import hmac
import logging
import threading
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

from . import build_sentinel
from .config import load
from .logstream import parse_batch

log = logging.getLogger(__name__)

settings = load()
sentinel = build_sentinel(settings)
_lock = threading.Lock()  # detector state is not thread-safe

app = FastAPI(title="Auth0 AI Sentinel")


def _check_auth(authorization: Optional[str]) -> None:
    if not settings.log_stream_secret:
        raise HTTPException(503, "AUTH0_LOG_STREAM_SECRET is not configured")
    if not authorization or not hmac.compare_digest(authorization, settings.log_stream_secret):
        raise HTTPException(401, "bad log stream credentials")


def _process(items: List[Dict[str, Any]]) -> None:
    with _lock:
        for item in items:
            try:
                sentinel.process(item)
            except Exception:
                log.exception("Failed processing log %s", item.get("log_id"))


@app.post("/auth0/logs", status_code=200)
async def receive(request: Request, background: BackgroundTasks,
                  authorization: Optional[str] = Header(None)) -> Dict[str, int]:
    _check_auth(authorization)
    try:
        items = parse_batch(await request.body())
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(400, "body is not JSON")
    background.add_task(_process, items)
    return {"accepted": len(items)}


@app.get("/healthz")
def health() -> Dict[str, str]:
    return {"status": "ok"}
