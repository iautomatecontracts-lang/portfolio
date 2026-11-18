"""The agent loop: score -> (optionally) ask Claude -> alert -> (optionally) contain."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional

import httpx

from .analyst import ClaudeAnalyst, Verdict
from .auth0 import Auth0Client
from .config import Settings
from .detector import Detection, Detector

log = logging.getLogger(__name__)
alert_log = logging.getLogger("auth0_ai_sentinel.alerts")


@dataclass
class Alert:
    severity: str  # high | medium
    title: str
    actor_id: str
    actor_name: str
    log_id: str
    log_type: str
    date: str
    client_ip: Optional[str]
    user_agent: Optional[str]
    heuristic_score: float
    signals: List[Dict[str, Any]]
    verdict: Optional[Dict[str, Any]]
    action_taken: str


class Sentinel:
    def __init__(self, settings: Settings, analyst: Optional[ClaudeAnalyst] = None,
                 auth0: Optional[Auth0Client] = None,
                 sinks: Optional[Iterable[Callable[[Alert], None]]] = None):
        self.s = settings
        self.detector = Detector(settings.window_seconds, settings.allowlist)
        self.analyst = analyst
        self.auth0 = auth0
        self.sinks = list(sinks) if sinks is not None else self._default_sinks()

    def process(self, item: Dict[str, Any]) -> Optional[Alert]:
        det = self.detector.analyze(item)
        if det is None or det.score < self.s.triage_threshold:
            return None

        verdict: Optional[Verdict] = None
        if self.analyst is not None:
            verdict = self.analyst.triage(det, self.detector.recent_activity(det.actor_id))

        if not self._should_alert(det, verdict):
            return None

        alert = self._build_alert(det, verdict)
        alert.action_taken = self._respond(det, verdict)
        for sink in self.sinks:
            try:
                sink(alert)
            except Exception:  # an alert sink must never break detection
                log.exception("Alert sink failed")
        return alert

    def _should_alert(self, det: Detection, verdict: Optional[Verdict]) -> bool:
        if verdict is None:
            return det.score >= self.s.flag_threshold
        if verdict.is_ai:
            return True
        return det.score >= 0.9 and verdict.classification == "inconclusive"

    def _build_alert(self, det: Detection, verdict: Optional[Verdict]) -> Alert:
        if verdict and verdict.is_ai:
            severity = "high" if verdict.confidence >= 0.8 else "medium"
            title = f"AI agent calling Auth0 as {det.actor_name} ({verdict.confidence:.0%} confidence)"
        else:
            severity = "high" if det.score >= 0.85 else "medium"
            title = f"Possible AI/automated client on Auth0 as {det.actor_name} (score {det.score:.2f})"
        return Alert(
            severity=severity,
            title=title,
            actor_id=det.actor_id,
            actor_name=det.actor_name,
            log_id=det.log_id,
            log_type=det.log_type,
            date=det.date,
            client_ip=det.client_ip,
            user_agent=det.user_agent,
            heuristic_score=det.score,
            signals=[asdict(s) for s in det.signals],
            verdict=asdict(verdict) if verdict else None,
            action_taken="none",
        )

    def _respond(self, det: Detection, verdict: Optional[Verdict]) -> str:
        mode = self.s.auto_response
        if mode == "none" or self.auth0 is None:
            return "none"
        # Containment requires Claude's agreement, not heuristics alone.
        if not (verdict and verdict.is_ai and verdict.recommended_action == "contain"
                and verdict.confidence >= self.s.auto_response_min_confidence):
            return "none"
        user_id = det.raw_event.get("user_id")
        if not user_id:
            return "skipped: actor is an application, not a user (review its client grants)"
        try:
            if mode == "revoke_sessions":
                self.auth0.revoke_sessions(user_id)
                return "revoked sessions and refresh tokens"
            if mode == "block":
                self.auth0.block_user(user_id)
                return "blocked user"
        except httpx.HTTPError as e:
            log.error("Auto-response failed for %s: %s", user_id, e)
            return f"failed: {e}"
        return "none"

    def _default_sinks(self) -> List[Callable[[Alert], None]]:
        sinks: List[Callable[[Alert], None]] = [log_sink]
        if self.s.slack_webhook_url:
            sinks.append(make_slack_sink(self.s.slack_webhook_url))
        return sinks


def log_sink(alert: Alert) -> None:
    alert_log.warning(json.dumps(asdict(alert), default=str))


def make_slack_sink(webhook_url: str) -> Callable[[Alert], None]:
    def send(alert: Alert) -> None:
        v = alert.verdict or {}
        lines = [
            f":rotating_light: *{alert.title}*",
            f"*Log:* `{alert.log_type}` at {alert.date} (`{alert.log_id}`)",
            f"*IP:* {alert.client_ip}   *UA:* `{(alert.user_agent or 'n/a')[:120]}`",
            f"*Signals:* {', '.join(s['name'] for s in alert.signals) or 'none'}",
        ]
        if v:
            lines.append(f"*Claude:* {v['classification']} -> {v['recommended_action']}. {v['rationale']}")
        if alert.action_taken != "none":
            lines.append(f"*Action taken:* {alert.action_taken}")
        httpx.post(webhook_url, json={"text": "\n".join(lines)}, timeout=10)

    return send
