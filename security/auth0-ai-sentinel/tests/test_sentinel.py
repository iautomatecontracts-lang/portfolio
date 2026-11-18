"""Offline tests: no Auth0 or Claude calls are made."""

from __future__ import annotations

from pathlib import Path

from auth0_ai_sentinel.analyst import Verdict
from auth0_ai_sentinel.config import Settings
from auth0_ai_sentinel.detector import Detector, combine
from auth0_ai_sentinel.logstream import parse_batch
from auth0_ai_sentinel.sentinel import Sentinel

SAMPLE_FILE = Path(__file__).parent.parent / "samples" / "logs.json"


def _log(log_id, ua="Chrome 131.0.0 / Mac OS X 10.15.7", ts="2026-11-10T15:00:00.000Z",
         user="auth0|u1", **extra):
    e = {
        "log_id": log_id,
        "date": ts,
        "type": "s",
        "client_id": "web",
        "client_name": "Portal",
        "ip": "203.0.113.5",
        "user_agent": ua,
        "user_id": user,
        "user_name": f"{user.split('|')[-1]}@corp.com",
    }
    e.update(extra)
    return e


class FakeAnalyst:
    def __init__(self, verdict):
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


def test_browser_login_scores_low():
    assert Detector().analyze(_log("a")).score < 0.2


def test_unparsed_auth0_user_agent_is_non_browser():
    det = Detector().analyze(_log("b", ua="Other 0.0.0 / Other 0.0.0"))
    assert det.signal_names == ["non_browser_client"]


def test_raw_user_agent_in_details_is_preferred():
    det = Detector().analyze(_log("c", ua="Other 0.0.0 / Other 0.0.0",
                                  details={"request": {"userAgent": "Anthropic/Python 1.2.0"}}))
    assert "ai_user_agent" in det.signal_names
    assert "non_browser_client" not in det.signal_names
    assert det.user_agent == "Anthropic/Python 1.2.0"


def test_headless_chrome_summary_detected():
    det = Detector().analyze(_log("d", ua="HeadlessChrome 131.0.0 / Linux 0.0.0"))
    assert "headless_browser" in det.signal_names


def test_ai_named_application():
    det = Detector().analyze(_log("e", client_name="Claude MCP Connector"))
    assert "ai_named_application" in det.signal_names


def test_token_vault_exchange_is_strongest_grant():
    det = Detector().analyze(_log("f", type="sertft", details={
        "grant_type": "urn:auth0:params:oauth:grant-type:token-exchange:federated-connection-access-token"}))
    grant = [s for s in det.signals if s.name == "agentic_oauth_grant"]
    assert grant and grant[0].weight == 0.55


def test_client_credentials_implied_by_type_code():
    det = Detector().analyze(_log("g", type="seccft", user=""))
    assert "agentic_oauth_grant" in det.signal_names
    assert det.actor_id == "client:web"


def test_auth0_sdk_not_generic_script():
    det = Detector().analyze(_log("h", details={"request": {"userAgent": "node-auth0/4.10.0 node.js/20"}}))
    assert "auth0_sdk_client" in det.signal_names
    assert "scripted_http_client" not in det.signal_names


def test_machine_timing_and_retries():
    d = Detector()
    det = None
    for i in range(12):
        det = d.analyze(_log(f"t{i}", type="fp", ts=f"2026-11-10T15:00:{i * 5:02d}.000Z"))
    assert {"machine_timing", "retry_after_errors"} <= set(det.signal_names)


def test_mgmt_api_enumeration():
    d = Detector()
    det = None
    for i in range(30):
        det = d.analyze(_log(f"m{i}", type="sapi", user="", ts=f"2026-11-10T15:{i // 6:02d}:{(i % 6) * 10:02d}.000Z",
                             details={"request": {"method": "patch", "path": f"/api/v2/users/auth0|{i}"}}))
    assert "enumeration" in det.signal_names


def test_duplicates_and_allowlist_ignored():
    d = Detector(allowlist=frozenset({"svc@corp.com"}))
    assert d.analyze(_log("dup")) is not None
    assert d.analyze(_log("dup")) is None
    assert d.analyze(_log("x", user="auth0|svc")) is None


def test_log_stream_wrapper_unwrapped():
    det = Detector().analyze({"log_id": "w1", "data": _log("w1", ua="langchain/0.3")})
    assert det.log_id == "w1" and "ai_user_agent" in det.signal_names


# --- log stream parsing ------------------------------------------------------


def test_parse_batch_formats():
    assert len(parse_batch(b'[{"a":1},{"b":2}]')) == 2
    assert len(parse_batch(b'{"a":1}\n{"b":2}\n')) == 2
    assert len(parse_batch(b'{"log_id":"x","data":{}}')) == 1
    assert parse_batch(b"") == []


# --- sentinel pipeline ---------------------------------------------------------


def test_heuristic_only_alerts_above_threshold():
    alerts = []
    s = Sentinel(_settings(), sinks=[alerts.append])
    s.process(_log("1"))
    s.process(_log("2", ua="OpenAI/Python 1.54.0", user="auth0|u2"))
    assert [a.log_id for a in alerts] == ["2"]


def test_claude_can_veto_alert():
    v = Verdict("automation", 0.9, "none", "Nightly sync job.", [], "claude-opus-5-5")
    alerts = []
    s = Sentinel(_settings(), analyst=FakeAnalyst(v), sinks=[alerts.append])
    s.process(_log("3", ua="python-requests/2.32 OpenAI"))
    assert alerts == []


def test_claude_confirms_alert_and_no_auto_response_by_default():
    v = Verdict("ai_agent", 0.93, "contain", "LLM agent enumerating users.", ["ua"], "claude-opus-5-5")
    alerts = []
    s = Sentinel(_settings(), analyst=FakeAnalyst(v), sinks=[alerts.append])
    a = s.process(_log("4", ua="langchain/0.3"))
    assert a.severity == "high" and a.verdict["classification"] == "ai_agent"
    assert a.action_taken == "none"


def test_low_score_skips_claude():
    fake = FakeAnalyst(None)
    Sentinel(_settings(), analyst=fake, sinks=[]).process(_log("5"))
    assert fake.calls == 0


def test_sample_file_flags_only_ai_events():
    alerts = []
    s = Sentinel(_settings(), sinks=[alerts.append])
    for item in parse_batch(SAMPLE_FILE.read_bytes()):
        s.process(item)
    flagged = {a.log_id for a in alerts}
    assert flagged == {
        "90020261110140540000000000000002",  # MCP server, client credentials
        "90020261110140903000000000000003",  # headless browser login
        "90020261110141000000000000000004",  # AI agent app via Token Vault exchange
    }
