"""Parsing for Auth0 Log Stream payloads (JSON array, JSON lines, or one object)."""

from __future__ import annotations

import json
from typing import Any, Dict, List


def parse_batch(raw: bytes) -> List[Dict[str, Any]]:
    text = raw.decode("utf-8").strip()
    if not text:
        return []
    try:
        body = json.loads(text)
    except json.JSONDecodeError:  # JSON Lines
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        return body.get("logs") or [body]
    return []
