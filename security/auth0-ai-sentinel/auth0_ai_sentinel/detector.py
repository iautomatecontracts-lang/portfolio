"""Heuristic detection of AI / agentic clients in Auth0 tenant logs.

Each Auth0 log event is scored from independent signals. Signals combine as
1 - prod(1 - weight), so several weak signals add up without exceeding 1.0.
Per-actor history (timing, burst rate, enumeration, retries) is kept in a
sliding window.

Auth0 log format: https://auth0.com/docs/deploy-monitor/logs/log-event-type-codes
"""

from __future__ import annotations

import re
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

# ---------------------------------------------------------------------------
# Signal dictionaries
# ---------------------------------------------------------------------------

# Names of AI products, LLM SDKs and agent frameworks.
AI_AGENT_UA = re.compile(
    r"(openai|anthropic|claude|chatgpt|gpt-?bot|oai-searchbot|perplexity|"
    r"langchain|langgraph|llama[-_ ]?index|autogen|crewai|semantic[-_ ]?kernel|"
    r"haystack|dspy|smolagents|browser[-_ ]?use|computer[-_ ]?use|"
    r"\bmcp\b|model[-_ ]?context[-_ ]?protocol|google-extended|gemini|copilot|"
    r"cohere|mistral|bedrock[-_ ]?agent|vertex[-_ ]?ai|agentforce|devin|cursor|"
    r"\bai[-_ ]?agent\b|\bllm\b)",
    re.IGNORECASE,
)

HEADLESS_UA = re.compile(
    r"(headlesschrome|headless ?chrome|chrome headless|playwright|puppeteer|selenium|webdriver|phantomjs|chrome-lighthouse)",
    re.IGNORECASE,
)

SCRIPTED_UA = re.compile(
    r"(python-httpx|python-requests|aiohttp|python-urllib|axios|node-fetch|undici|"
    r"got \(|go-http-client|curl/|wget/|okhttp|java/|apache-httpclient|"
    r"postmanruntime|insomnia|rest-client|ruby|guzzle|libwww-perl|powershell)",
    re.IGNORECASE,
)

# Official Auth0 SDKs / tooling: scripted, but usually sanctioned automation.
AUTH0_SDK_UA = re.compile(
    r"(auth0-python|node-auth0|auth0-java|auth0-go|auth0-deploy-cli|terraform-provider-auth0|auth0-cli)",
    re.IGNORECASE,
)

# OAuth grants used for machine access or for agents acting for a user.
# Federated connection token exchange is what Auth0 Token Vault (Auth0 for AI
# Agents) uses to hand third-party API tokens to an agent.
AGENTIC_GRANTS = {
    "client_credentials": 0.30,
    "urn:ietf:params:oauth:grant-type:jwt-bearer": 0.35,
    "urn:ietf:params:oauth:grant-type:token-exchange": 0.45,
    "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token": 0.55,
    "urn:ietf:params:oauth:token-type:id-jag": 0.55,
}

# Auth0 log type codes that imply a grant even when details are sparse.
TYPE_IMPLIED_GRANT = {
    "seccft": "client_credentials",  # success: client credentials -> access token
    "secte": "urn:ietf:params:oauth:grant-type:token-exchange",  # success: custom token exchange
}

MGMT_API_TYPES = {"sapi", "fapi"}  # Management API operation (success / failure)


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class Signal:
    name: str
    weight: float
    detail: str


@dataclass
class Detection:
    log_id: str
    log_type: str
    date: str
    actor_id: str
    actor_name: str
    client_ip: Optional[str]
    user_agent: Optional[str]
    score: float
    signals: List[Signal]
    raw_event: Dict[str, Any] = field(repr=False)

    @property
    def signal_names(self) -> List[str]:
        return [s.name for s in self.signals]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(d: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def _parse_ts(ts: Optional[str]) -> Optional[float]:
    if not ts:
        return None
    try:
        # Auth0 uses e.g. 2026-11-10T14:02:11.123Z; fromisoformat on 3.9 needs
        # an explicit offset and at most 6 fractional digits.
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _strings(obj: Any, depth: int = 0) -> Iterable[str]:
    """All string values in a nested structure (bounded depth)."""
    if depth > 6:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v, depth + 1)


def combine(weights: Iterable[float]) -> float:
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - max(0.0, min(w, 1.0))
    return round(1.0 - remaining, 3)


def unwrap(item: Dict[str, Any]) -> Dict[str, Any]:
    """Log Streams wrap each event as {"log_id": ..., "data": {...}}; the Management API doesn't."""
    if "data" in item and isinstance(item["data"], dict) and "type" in item["data"]:
        event = dict(item["data"])
        event.setdefault("log_id", item.get("log_id"))
        return event
    return item


# Auth0 stores a parsed summary in `user_agent` ("Chrome 131.0.0 / Mac OS X 10.15.7").
# Unrecognized clients (most SDKs and scripts) collapse to "Other 0.0.0 / Other 0.0.0".
UNPARSED_UA = re.compile(r"^other [\d.]+ / other [\d.]+$", re.IGNORECASE)


def user_agent_of(event: Dict[str, Any]) -> Optional[str]:
    """Prefer the raw user agent when the log carries one; fall back to Auth0's summary."""
    for raw in (
        _get(event, "details", "request", "userAgent"),
        _get(event, "details", "request", "headers", "user-agent"),
        _get(event, "details", "userAgent"),
    ):
        if raw:
            return raw
    return event.get("user_agent")


def actor_of(event: Dict[str, Any]) -> str:
    if event.get("user_id"):
        return event["user_id"]
    if event.get("client_id"):
        return f"client:{event['client_id']}"
    return f"ip:{event.get('ip') or 'unknown'}"


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


@dataclass
class _ActorHistory:
    timestamps: deque = field(default_factory=lambda: deque(maxlen=200))
    paths: deque = field(default_factory=lambda: deque(maxlen=500))  # (ts, mgmt API path)
    failures: deque = field(default_factory=lambda: deque(maxlen=200))  # ts of failed events
    events: deque = field(default_factory=lambda: deque(maxlen=50))  # compact summaries


class Detector:
    def __init__(self, window_seconds: int = 900, allowlist: frozenset = frozenset()):
        self.window = window_seconds
        self.allowlist = allowlist
        self._history: Dict[str, _ActorHistory] = defaultdict(_ActorHistory)
        self._seen: deque = deque(maxlen=20_000)
        self._seen_set: set = set()

    # -- public ------------------------------------------------------------

    def analyze(self, item: Dict[str, Any]) -> Optional[Detection]:
        """Score one Auth0 log event. Returns None for duplicates and allowlisted actors."""
        event = unwrap(item)
        log_id = event.get("log_id") or event.get("_id") or ""
        if log_id and log_id in self._seen_set:
            return None
        self._remember(log_id)

        ids = {
            str(event.get(k) or "").lower()
            for k in ("user_id", "user_name", "client_id")
        } - {""}
        if ids & self.allowlist:
            return None

        actor = actor_of(event)
        ts = _parse_ts(event.get("date"))
        ua = user_agent_of(event)
        hist = self._history[actor]
        self._record(hist, event, ts)

        signals: List[Signal] = []
        signals += self._user_agent_signals(ua, event.get("user_agent"))
        signals += self._client_signals(event)
        signals += self._grant_signals(event)
        signals += self._behavior_signals(hist, ts)
        signals += self._auth0_risk_signals(event)

        return Detection(
            log_id=log_id,
            log_type=event.get("type", ""),
            date=event.get("date", ""),
            actor_id=actor,
            actor_name=event.get("user_name") or event.get("client_name") or actor,
            client_ip=event.get("ip"),
            user_agent=ua,
            score=combine(s.weight for s in signals),
            signals=signals,
            raw_event=event,
        )

    def recent_activity(self, actor_id: str) -> List[Dict[str, Any]]:
        return list(self._history[actor_id].events)

    # -- bookkeeping ---------------------------------------------------------

    def _remember(self, log_id: str) -> None:
        if not log_id:
            return
        if len(self._seen) == self._seen.maxlen:
            self._seen_set.discard(self._seen[0])
        self._seen.append(log_id)
        self._seen_set.add(log_id)

    def _record(self, hist: _ActorHistory, event: Dict[str, Any], ts: Optional[float]) -> None:
        path = _get(event, "details", "request", "path")
        if ts is not None:
            hist.timestamps.append(ts)
            if path:
                hist.paths.append((ts, path))
            if str(event.get("type", "")).startswith("f"):
                hist.failures.append(ts)
        hist.events.append(
            {
                "date": event.get("date"),
                "type": event.get("type"),
                "description": event.get("description"),
                "client": event.get("client_name"),
                "ip": event.get("ip"),
                "userAgent": event.get("user_agent"),
                "method": _get(event, "details", "request", "method"),
                "path": path,
            }
        )

    # -- signal groups ---------------------------------------------------------

    def _user_agent_signals(self, ua: Optional[str], summary: Optional[str]) -> List[Signal]:
        if not ua:
            return [Signal("missing_user_agent", 0.20, "No user agent on the request")]
        out: List[Signal] = []
        if summary and UNPARSED_UA.match(summary.strip()) and ua == summary:
            out.append(Signal("non_browser_client", 0.30, "Auth0 could not identify a browser or OS (SDK/script)"))
        m = AI_AGENT_UA.search(ua)
        if m:
            out.append(Signal("ai_user_agent", 0.75, f"User agent names an AI client: '{m.group(0)}'"))
        m = HEADLESS_UA.search(ua)
        if m:
            out.append(Signal("headless_browser", 0.60, f"Automated browser: '{m.group(0)}'"))
        if AUTH0_SDK_UA.search(ua):
            out.append(Signal("auth0_sdk_client", 0.10, "Official Auth0 SDK / tooling"))
        else:
            m = SCRIPTED_UA.search(ua)
            if m:
                out.append(Signal("scripted_http_client", 0.35, f"Scripted HTTP client: '{m.group(0)}'"))
        return out

    def _client_signals(self, event: Dict[str, Any]) -> List[Signal]:
        # Admins often name the Auth0 application after the agent it serves
        # ("Claude MCP connector", "Support AI agent").
        name = event.get("client_name") or ""
        m = AI_AGENT_UA.search(name)
        if m:
            return [Signal("ai_named_application", 0.35, f"Auth0 application name suggests AI: '{name}'")]
        return []

    def _grant_signals(self, event: Dict[str, Any]) -> List[Signal]:
        out: List[Signal] = []
        haystack = " ".join(_strings(event.get("details"))).lower()
        haystack += " " + str(event.get("grant_type") or "").lower()
        implied = TYPE_IMPLIED_GRANT.get(event.get("type", ""))
        if implied:
            haystack += " " + implied
        matches = [(w, g) for g, w in AGENTIC_GRANTS.items() if g in haystack]
        if matches:
            weight, grant = max(matches)
            out.append(Signal("agentic_oauth_grant", weight, f"OAuth grant/token type: {grant}"))

        if event.get("type") in MGMT_API_TYPES:
            out.append(Signal("management_api_call", 0.15, "Direct Auth0 Management API operation"))
        return out

    def _behavior_signals(self, hist: _ActorHistory, now: Optional[float]) -> List[Signal]:
        if now is None:
            return []
        out: List[Signal] = []
        recent = [t for t in hist.timestamps if now - t <= self.window]

        last_min = [t for t in recent if now - t <= 60]
        if len(last_min) >= 20:
            out.append(Signal("burst_rate", 0.40, f"{len(last_min)} events in the last 60s"))
        elif len(last_min) >= 8:
            out.append(Signal("elevated_rate", 0.20, f"{len(last_min)} events in the last 60s"))

        if len(recent) >= 8:
            ordered = sorted(recent)
            gaps = [b - a for a, b in zip(ordered, ordered[1:]) if b - a > 0]
            if len(gaps) >= 6:
                mean = statistics.fmean(gaps)
                cv = statistics.pstdev(gaps) / mean if mean else 0
                if cv < 0.15:
                    out.append(Signal("machine_timing", 0.45, f"Inter-request timing CV={cv:.2f} (regular loop)"))
                elif cv < 0.30:
                    out.append(Signal("regular_timing", 0.20, f"Inter-request timing CV={cv:.2f}"))

        distinct = {p for t, p in hist.paths if now - t <= self.window}
        if len(distinct) >= 25:
            out.append(Signal("enumeration", 0.40, f"{len(distinct)} distinct Management API paths in window"))

        fails = [t for t in hist.failures if now - t <= self.window]
        if len(fails) >= 5:
            out.append(Signal("retry_after_errors", 0.20, f"{len(fails)} failed calls in window (trial and error)"))
        return out

    def _auth0_risk_signals(self, event: Dict[str, Any]) -> List[Signal]:
        out: List[Signal] = []
        t = event.get("type", "")
        if t in {"limit_wc", "limit_sul", "limit_mu"}:
            out.append(Signal("auth0_rate_limited", 0.25, f"Auth0 attack protection blocked the source ({t})"))
        risk = _get(event, "details", "riskAssessment", "confidence")
        if str(risk).lower() == "low":
            out.append(Signal("auth0_low_risk_confidence", 0.25, "Auth0 risk assessment: low confidence in this login"))
        return out
