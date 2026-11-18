# Auth0 AI Sentinel

A security agent that watches your Auth0 tenant logs and flags when **an AI system is
calling your tenant**: LLM agents, agent frameworks, MCP servers, browser and computer-use
agents, apps using Token Vault (Auth0 for AI Agents), or code that an LLM is running.

```
Auth0 tenant logs ──► Log Stream webhook (push) ─┐
                  └─► Management API poller (pull) ─┴─► Heuristic detector ──► Claude triage ──► Alert (log / Slack)
                                                         (score 0..1)          (verdict + why)     └─► optional containment
```

## How detection works

**1. Heuristics** (`auth0_ai_sentinel/detector.py`):

| Signal | Example | Weight |
|---|---|---|
| AI client user agent | `Anthropic/Python`, `OpenAI/Python`, `langchain`, `mcp-python-sdk` | 0.75 |
| Headless / automated browser | `HeadlessChrome 131.0.0 / Linux` | 0.60 |
| Delegated agent OAuth grant | Token Vault federated-connection exchange, ID-JAG, token exchange (`secte`), JWT bearer, client credentials (`seccft`) | 0.30–0.55 |
| Machine timing | steady gaps between requests | 0.45 |
| Burst rate / Management API enumeration | 20+ events/min, 25+ distinct `/api/v2/...` paths in the window | 0.40 |
| AI-named Auth0 application | `client_name` such as "Claude MCP Connector" or "Support AI Agent" | 0.35 |
| Scripted HTTP client | `python-httpx`, `requests`, `axios`, `curl` | 0.35 |
| Non-browser client | Auth0 summary `Other 0.0.0 / Other 0.0.0` | 0.30 |
| Retries after errors, attack protection (`limit_*`), low risk-assessment confidence, Management API call | | 0.15–0.25 |

Auth0 stores a **parsed** user agent (for example `Chrome 131.0.0 / Mac OS X 10.15.7`).
When a log includes the raw one (`details.request.userAgent`, as on Management API logs),
the detector uses that instead. Official Auth0 SDKs, the Deploy CLI and the Terraform
provider get a low weight. Anything on `ALLOWLIST` is ignored.

**2. Claude triage** (`auth0_ai_sentinel/analyst.py`). Events at or above
`TRIAGE_THRESHOLD` go to Claude (`claude-opus-5-5`) with the actor's recent timeline. Claude
returns `ai_agent | automation | human | inconclusive`, a confidence, a recommended action
and a short rationale. Request bodies and tokens are stripped before anything is sent.
Log fields are passed as delimited, untrusted data, because user agents and names are
attacker-controlled.

**3. Alert and respond** (`auth0_ai_sentinel/sentinel.py`). Alerts go to stdout as JSON
and to Slack if `SLACK_WEBHOOK_URL` is set. **By default it only flags.** With
`AUTO_RESPONSE=revoke_sessions|block`, it acts only on a user (never an application),
and only when Claude says `ai_agent`, recommends `contain`, and has confidence at or above
`AUTO_RESPONSE_MIN_CONFIDENCE`.

## Setup

Requires **Python 3.10+** (the current Anthropic SDK does not support 3.9).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # fill in, then: set -a; source .env; set +a
pytest -q               # offline tests, no Auth0 or Claude calls
python -m auth0_ai_sentinel replay samples/logs.json
```

### Auth0 credentials

In the Auth0 Dashboard go to **Applications → Create Application → Machine to Machine**,
authorize it for the **Auth0 Management API**, and grant `read:logs`. Add `update:users`,
`delete:sessions` and `delete:refresh_tokens` only if you turn on `AUTO_RESPONSE`.

### Option A: Real time with a Log Stream (recommended)

1. Deploy `python -m auth0_ai_sentinel serve --port 8080` behind HTTPS.
2. In the Auth0 Dashboard go to **Monitoring → Streams → Create Log Stream → Custom Webhook**:
   - Payload URL: `https://<your-host>/auth0/logs`
   - Authorization Token: the value of `AUTH0_LOG_STREAM_SECRET`
   - Content Type `application/json`. Content Format can be JSON Array, JSON Lines or JSON Object.
   - Filter: all categories, or at least Login, Token Exchange, Management API, Signup,
     Attack Protection and Errors.

### Option B: Poll the Management API

```bash
python -m auth0_ai_sentinel poll --interval 60
```
It seeds from the latest 100 logs, then reads forward from that `log_id` checkpoint.

## Tuning

- Put sanctioned automation on `ALLOWLIST` by `user_id`, email or `client_id`
  (CI deploys, SCIM, backend services).
- Set `CLAUDE_TRIAGE=false` to run on heuristics only (alerts at `FLAG_THRESHOLD`).
- Run `replay` on an export of your own tenant logs to measure false positives first.

## Limits

- Auth0 logs record logins, token exchanges, signups and Management API **writes**.
  Read-only Management API calls and calls to your own APIs are not logged. Detection
  covers what Auth0 logs.
- Auth0 logs have no ASN or ISP data, so cloud-hosted sources can't be flagged by network.
  Enrich `ip` with a GeoIP/ASN database if you need that.
- User agents can be spoofed. A careful agent using a real browser is caught only by its
  behavior and by Claude's review of the timeline.
- Detector state is in-memory per process. Run a single instance, or move history to Redis.
