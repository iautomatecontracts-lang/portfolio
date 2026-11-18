"""Offline tests: no Okta or Claude calls are made."""

from __future__ import annotations

import json
from pathlib import Path

from okta_ai_sentinel.analyst import Verdict
from okta_ai_sentinel.config import Settings
from okta_ai_sentinel.detector import Detector, combine
from okta_ai_sentinel.sentinel import Sentinel

SAMPLES = json.loads((Path(__file__).parent.parent / "samples" / "events.json").read_text())


def _event(uuid: str, ua: str, ts: str = "2026-11-10T15:00:00.000Z", actor="00u1", **extra):
    e = {
        "uuid": uuid,
        "published": ts,
        "eventType": "user.session.start",
        "actor": {"id": actor, "type": "User", "alternateId": f"{actor}@corp.com", "displayName": actor},
        "client": {"userAgent": {"rawUserAgent": ua}, "ipAddress": "203.0.113.5"},
        "outcome": {"result": "SUCCESS"},
    }
    e.update(extra)
    return e


class FakeAnalyst:
    def __init__(self, verdict: Verdict | None):
        self.verdict, self.calls = verdict, 0

    def triage(self, det, history):
        self.calls += 1
        return self.verdict


def _settings(**kw) -> Settings:
    return Settings(**{"anthropic_enabled": False, "slack_webhook_url": "", "auto_response": "none", **kw})


# --- detector ---------------------------------------------------------------


def test_combine_is_bounded():
    assert combine([]) == 0
    assert combine([0.5, 0.5]) == 0.75
    assert combine([1.0, 0.3]) == 1.0


def test_browser_login_scores_low():
    d = Detector()
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15"
    assert d.analyze(_event("a", ua)).score < 0.2


def test_ai_sdk_user_agent_is_flagged():
    det = Detector().analyze(_event("b", "Anthropic/Python 0.71.0"))
    assert "ai_user_agent" in det.signal_names
    assert det.score >= 0.75


def test_langchain_over_httpx_stacks_signals():
    det = Detector().analyze(_event("c", "python-httpx/0.27.0 langchain-core/0.3"))
    assert {"ai_user_agent", "scripted_http_client"} <= set(det.signal_names)
    assert det.score > 0.8


def test_okta_sdk_is_not_treated_as_generic_script():
    det = Detector().analyze(_event("d", "okta-sdk-python/2.9.0 python/3.12"))
    assert "okta_sdk_client" in det.signal_names
    assert "scripted_http_client" not in det.signal_names


def test_id_jag_grant_is_agentic():
    e = _event("e", "Mozilla/5.0", eventType="app.oauth2.as.token.grant.access_token",
               debugContext={"debugData": {"grantType": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                           "subjectTokenType": "urn:ietf:params:oauth:token-type:id-jag"}})
    det = Detector().analyze(e)
    assert any(s.name == "agentic_oauth_grant" and s.weight == 0.55 for s in det.signals)


def test_metronomic_timing_detected():
    d = Detector()
    det = None
    for i in range(12):
        det = d.analyze(_event(f"t{i}", "Mozilla/5.0", ts=f"2026-11-10T15:00:{i * 5:02d}.000Z"))
    assert "machine_timing" in det.signal_names


def test_duplicates_and_allowlist_ignored():
    d = Detector(allowlist=frozenset({"svc@corp.com"}))
    assert d.analyze(_event("dup", "curl/8.0")) is not None
    assert d.analyze(_event("dup", "curl/8.0")) is None
    assert d.analyze(_event("x", "curl/8.0", actor="svc")) is None


def test_untrusted_cloud_network():
    det = Detector().analyze(_event("n", "Mozilla/5.0", securityContext={"asOrg": "Amazon.com, Inc.", "isProxy": False}))
    assert "cloud_network" in det.signal_names


# --- sentinel pipeline ---------------------------------------------------------


def test_heuristic_only_alerts_above_threshold():
    alerts = []
    s = Sentinel(_settings(), sinks=[alerts.append])
    s.process(_event("1", "Mozilla/5.0 Safari"))
    s.process(_event("2", "OpenAI/Python 1.54.0", actor="00u2"))
    assert [a.event_uuid for a in alerts] == ["2"]


def test_claude_can_veto_alert():
    v = Verdict("automation", 0.9, "none", "Nightly SCIM sync.", [], "claude-opus-5-5")
    alerts = []
    s = Sentinel(_settings(), analyst=FakeAnalyst(v), sinks=[alerts.append])
    s.process(_event("3", "python-requests/2.32 OpenAI"))
    assert alerts == []


def test_claude_confirms_alert_and_no_auto_response_by_default():
    v = Verdict("ai_agent", 0.93, "contain", "LLM agent enumerating users.", ["ua"], "claude-opus-5-5")
    alerts = []
    s = Sentinel(_settings(), analyst=FakeAnalyst(v), sinks=[alerts.append])
    a = s.process(_event("4", "langchain/0.3"))
    assert a.severity == "high" and a.verdict["classification"] == "ai_agent"
    assert a.action_taken == "none"


def test_low_score_skips_claude():
    fake = FakeAnalyst(None)
    s = Sentinel(_settings(), analyst=fake, sinks=[])
    s.process(_event("5", "Mozilla/5.0 Safari"))
    assert fake.calls == 0


def test_sample_file_flags_only_ai_events():
    alerts = []
    s = Sentinel(_settings(), sinks=[alerts.append])
    for e in SAMPLES["data"]["events"]:
        s.process(e)
    flagged = {a.event_uuid for a in alerts}
    assert "human-browser-login" not in flagged
    assert {"mcp-server-token", "headless-browser-agent"} <= flagged
    assert "okta-terraform" not in flagged
