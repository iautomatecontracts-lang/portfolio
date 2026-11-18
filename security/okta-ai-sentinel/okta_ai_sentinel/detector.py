"""Heuristic detection of AI / agentic clients in Okta System Log events.

Each Okta event is scored from independent signals. Signals are combined as
1 - prod(1 - weight), so several weak signals add up without exceeding 1.0.
Per-actor history (timing, burst rate, enumeration) is kept in a sliding window.
"""

from __future__ import annotations

import re
import statistics
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Signal dictionaries
# ---------------------------------------------------------------------------

# User agents that name an AI product, LLM SDK or agent framework outright.
AI_AGENT_UA = re.compile(
    r"(openai|anthropic|claude|chatgpt|gpt-?bot|oai-searchbot|perplexity|"
    r"langchain|langgraph|llama[-_ ]?index|autogen|crewai|semantic[-_ ]?kernel|"
    r"haystack|dspy|smolagents|browser[-_ ]?use|computer[-_ ]?use|"
    r"\bmcp\b|model[-_ ]?context[-_ ]?protocol|google-extended|gemini|copilot|"
    r"cohere|mistral|bedrock[-_ ]?agent|vertex[-_ ]?ai|agentforce|devin|cursor)",
    re.IGNORECASE,
)

# Headless / automated browsers: typical of computer-use and browsing agents.
HEADLESS_UA = re.compile(
    r"(headlesschrome|playwright|puppeteer|selenium|webdriver|phantomjs|"
    r"chrome-lighthouse|electron/.*headless)",
    re.IGNORECASE,
)

# Generic scripted HTTP clients. LLM SDKs are built on several of these
# (the OpenAI and Anthropic Python SDKs use httpx), so they are a medium signal.
SCRIPTED_UA = re.compile(
    r"(python-httpx|python-requests|aiohttp|python-urllib|axios|node-fetch|undici|"
    r"got \(|go-http-client|curl/|wget/|okhttp|java/|apache-httpclient|"
    r"postmanruntime|insomnia|rest-client|ruby|guzzle|libwww-perl|powershell)",
    re.IGNORECASE,
)

# Official Okta SDKs and tooling: scripted, but usually sanctioned automation.
OKTA_SDK_UA = re.compile(r"(okta-sdk|okta-terraform|okta-cli|okta-aws-cli)", re.IGNORECASE)

# Hosting / AI-provider networks. Humans rarely sign in from these.
CLOUD_NETWORK = re.compile(
    r"(amazon|aws|google cloud|google llc|microsoft|azure|digitalocean|linode|akamai|"
    r"ovh|hetzner|oracle cloud|cloudflare|fastly|vultr|openai|anthropic|"
    r"coreweave|lambda labs|runpod|scaleway|alibaba|tencent)",
    re.IGNORECASE,
)

# OAuth grant types used for machine or delegated-agent access. ID-JAG is the
# token type used by Cross App Access (XAA) for AI agents acting for a user.
AGENTIC_GRANTS = {
    "client_credentials": 0.30,
    "urn:ietf:params:oauth:grant-type:token-exchange": 0.45,
    "urn:ietf:params:oauth:grant-type:jwt-bearer": 0.35,
    "urn:ietf:params:oauth:token-type:id-jag": 0.55,
}

# Event types that read or enumerate directory data in bulk.
ENUMERATION_EVENTS = {
    "user.account.privilege.grant",
    "group.user_membership.add",
    "application.user_membership.add",
    "system.api_token.create",
    "user.lifecycle.create",
    "user.account.update_profile",
}


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
    event_uuid: str
    event_type: str
    published: str
    actor_id: str
    actor_name: str
    client_ip: str | None
    user_agent: str | None
    score: float
    signals: list[Signal]
    raw_event: dict[str, Any] = field(repr=False)

    @property
    def signal_names(self) -> list[str]:
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


def _parse_ts(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def combine(weights: Iterable[float]) -> float:
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - max(0.0, min(w, 1.0))
    return round(1.0 - remaining, 3)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


@dataclass
class _ActorHistory:
    timestamps: deque = field(default_factory=lambda: deque(maxlen=200))
    targets: deque = field(default_factory=lambda: deque(maxlen=500))  # (ts, target_id)
    events: deque = field(default_factory=lambda: deque(maxlen=50))  # compact summaries


class Detector:
    def __init__(self, window_seconds: int = 900, allowlist: frozenset[str] = frozenset()):
        self.window = window_seconds
        self.allowlist = allowlist
        self._history: dict[str, _ActorHistory] = defaultdict(_ActorHistory)
        self._seen: deque = deque(maxlen=20_000)
        self._seen_set: set[str] = set()

    # -- public ------------------------------------------------------------

    def analyze(self, event: dict[str, Any]) -> Detection | None:
        """Score one Okta event. Returns None for duplicates and allowlisted actors."""
        uuid = event.get("uuid") or ""
        if uuid and uuid in self._seen_set:
            return None
        self._remember(uuid)

        actor_id = _get(event, "actor", "id") or "unknown"
        actor_login = (_get(event, "actor", "alternateId") or "").lower()
        client_id = (_get(event, "debugContext", "debugData", "clientId") or "").lower()
        if {actor_id.lower(), actor_login, client_id} & self.allowlist:
            return None

        ts = _parse_ts(event.get("published"))
        ua = _get(event, "client", "userAgent", "rawUserAgent")
        hist = self._history[actor_id]
        self._record(hist, event, ts)

        signals: list[Signal] = []
        signals += self._user_agent_signals(event, ua)
        signals += self._credential_signals(event)
        signals += self._network_signals(event)
        signals += self._behavior_signals(hist, ts)
        signals += self._okta_risk_signals(event)

        return Detection(
            event_uuid=uuid,
            event_type=event.get("eventType", ""),
            published=event.get("published", ""),
            actor_id=actor_id,
            actor_name=_get(event, "actor", "displayName") or actor_login or actor_id,
            client_ip=_get(event, "client", "ipAddress"),
            user_agent=ua,
            score=combine(s.weight for s in signals),
            signals=signals,
            raw_event=event,
        )

    def recent_activity(self, actor_id: str) -> list[dict[str, Any]]:
        return list(self._history[actor_id].events)

    # -- bookkeeping ---------------------------------------------------------

    def _remember(self, uuid: str) -> None:
        if not uuid:
            return
        if len(self._seen) == self._seen.maxlen:
            self._seen_set.discard(self._seen[0])
        self._seen.append(uuid)
        self._seen_set.add(uuid)

    def _record(self, hist: _ActorHistory, event: dict[str, Any], ts: float | None) -> None:
        if ts is not None:
            hist.timestamps.append(ts)
            for t in event.get("target") or []:
                if t.get("id"):
                    hist.targets.append((ts, t["id"]))
        hist.events.append(
            {
                "published": event.get("published"),
                "eventType": event.get("eventType"),
                "outcome": _get(event, "outcome", "result"),
                "ip": _get(event, "client", "ipAddress"),
                "userAgent": _get(event, "client", "userAgent", "rawUserAgent"),
                "targets": [t.get("type") for t in event.get("target") or []],
            }
        )

    # -- signal groups ---------------------------------------------------------

    def _user_agent_signals(self, event: dict[str, Any], ua: str | None) -> list[Signal]:
        if not ua or ua.upper() == "UNKNOWN":
            return [Signal("missing_user_agent", 0.20, "No user agent on the request")]
        out: list[Signal] = []
        if m := AI_AGENT_UA.search(ua):
            out.append(Signal("ai_user_agent", 0.75, f"User agent names an AI client: '{m.group(0)}'"))
        if m := HEADLESS_UA.search(ua):
            out.append(Signal("headless_browser", 0.50, f"Automated browser: '{m.group(0)}'"))
        if OKTA_SDK_UA.search(ua):
            out.append(Signal("okta_sdk_client", 0.10, "Official Okta SDK / tooling"))
        elif m := SCRIPTED_UA.search(ua):
            out.append(Signal("scripted_http_client", 0.35, f"Scripted HTTP client: '{m.group(0)}'"))
        return out

    def _credential_signals(self, event: dict[str, Any]) -> list[Signal]:
        out: list[Signal] = []
        debug = _get(event, "debugContext", "debugData") or {}
        grant = str(debug.get("grantType") or "").lower()
        token_types = " ".join(
            str(debug.get(k) or "") for k in ("requestedTokenType", "subjectTokenType", "actorTokenType")
        ).lower()
        matches = [(w, m) for m, w in AGENTIC_GRANTS.items() if m == grant or m in token_types]
        if matches:
            weight, marker = max(matches)
            out.append(Signal("agentic_oauth_grant", weight, f"OAuth grant/token type: {marker}"))

        cred = str(_get(event, "authenticationContext", "credentialType") or "").upper()
        if cred in {"API_TOKEN", "SSWS"}:
            out.append(Signal("api_token_auth", 0.25, "Request authenticated with a static API token"))

        if event.get("eventType") == "system.api_token.create":
            out.append(Signal("api_token_created", 0.20, "New API token minted"))

        actor_type = str(_get(event, "actor", "type") or "")
        if actor_type in {"PublicClientApp", "AppInstance", "Client"}:
            out.append(Signal("non_human_actor", 0.15, f"Actor type is {actor_type}"))
        return out

    def _network_signals(self, event: dict[str, Any]) -> list[Signal]:
        out: list[Signal] = []
        sec = event.get("securityContext") or {}
        net = " ".join(str(sec.get(k) or "") for k in ("asOrg", "isp", "domain"))
        if net.strip() and (m := CLOUD_NETWORK.search(net)):
            out.append(Signal("cloud_network", 0.25, f"Request from hosting/AI network: '{m.group(0)}'"))
        if sec.get("isProxy"):
            out.append(Signal("proxy", 0.15, "Request routed through a proxy/anonymizer"))
        return out

    def _behavior_signals(self, hist: _ActorHistory, now: float | None) -> list[Signal]:
        if now is None:
            return []
        out: list[Signal] = []
        recent = [t for t in hist.timestamps if now - t <= self.window]

        # Burst rate: more events per minute than a human produces.
        last_min = [t for t in recent if now - t <= 60]
        if len(last_min) >= 20:
            out.append(Signal("burst_rate", 0.40, f"{len(last_min)} events in the last 60s"))
        elif len(last_min) >= 8:
            out.append(Signal("elevated_rate", 0.20, f"{len(last_min)} events in the last 60s"))

        # Metronomic timing: low variance between requests is a loop, not a person.
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

        # Enumeration: touching many distinct objects in the window.
        distinct = {tid for t, tid in hist.targets if now - t <= self.window}
        if len(distinct) >= 25:
            out.append(Signal("enumeration", 0.40, f"{len(distinct)} distinct objects touched in window"))
        return out

    def _okta_risk_signals(self, event: dict[str, Any]) -> list[Signal]:
        out: list[Signal] = []
        debug = _get(event, "debugContext", "debugData") or {}
        if str(debug.get("threatSuspected", "")).lower() == "true":
            out.append(Signal("okta_threat_suspected", 0.30, "Okta ThreatInsight flagged this request"))
        risk = str(debug.get("risk") or "")
        if "level=HIGH" in risk.upper().replace(" ", ""):
            out.append(Signal("okta_high_risk", 0.25, f"Okta risk: {risk}"))
        if event.get("eventType") in ENUMERATION_EVENTS and _get(event, "outcome", "result") == "FAILURE":
            out.append(Signal("failed_privileged_call", 0.15, "Failed privileged/admin call"))
        return out
