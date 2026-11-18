# Okta AI Sentinel

A security agent that watches your Okta org and flags when **an AI system is calling
the Okta API**: LLM agents, agent frameworks, MCP servers, browser and computer-use
agents, or code that an LLM is running.

```
Okta System Log ──► Event Hook (push)  ─┐
                └─► Poller (pull)      ─┴─► Heuristic detector ──► Claude triage ──► Alert (log / Slack)
                                             (score 0..1)          (verdict + why)     └─► optional containment
```

## How detection works

**1. Heuristics** (`okta_ai_sentinel/detector.py`) score every event using these signals:

| Signal | Example | Weight |
|---|---|---|
| AI client user agent | `Anthropic/Python`, `OpenAI/Python`, `langchain`, `mcp-python-sdk`, `GPTBot`, `ClaudeBot` | 0.75 |
| Headless / automated browser | `HeadlessChrome`, `Playwright`, `Puppeteer`, `Selenium` | 0.50 |
| Delegated agent OAuth grant | ID-JAG (Cross App Access), token exchange, JWT bearer, client credentials | 0.30–0.55 |
| Machine timing | steady gaps between requests (low coefficient of variation) | 0.45 |
| Burst rate / enumeration | 20+ events/min, 25+ distinct objects in the window | 0.40 |
| Scripted HTTP client | `python-httpx` (used by the OpenAI and Anthropic SDKs), `requests`, `axios`, `curl` | 0.35 |
| Cloud / AI-provider network | AWS, GCP, Azure, OpenAI, Anthropic ASNs | 0.25 |
| Static API token, Okta ThreatInsight, proxy | | 0.15–0.30 |

Signals combine as `1 − Π(1 − w)`. Official Okta SDKs and Terraform get a low weight,
and anything on `ALLOWLIST` is ignored.

**2. Claude triage** (`okta_ai_sentinel/analyst.py`). Events that score at or above
`TRIAGE_THRESHOLD` go to Claude (`claude-opus-5-5`) together with a timeline of the
actor's recent activity. Claude returns a structured verdict:
`ai_agent | automation | human | inconclusive`, a confidence, a recommended action and a
short rationale. This step is what tells an AI agent apart from a cron job: an agent
pauses between tool calls, explores, and retries after errors, while a script repeats
the same steady calls. Okta fields are passed to Claude as delimited, untrusted data,
because user agents and display names are attacker-controlled. Server-side refusal
fallback is on, so if one model declines a security prompt, another model gives the verdict.

**3. Alert and respond** (`okta_ai_sentinel/sentinel.py`). Alerts go to stdout as JSON
and to Slack if `SLACK_WEBHOOK_URL` is set. **By default it only flags and never changes
an account.** If you set `AUTO_RESPONSE=clear_sessions|suspend`, it acts only when
Claude classifies the activity as `ai_agent` with confidence at or above
`AUTO_RESPONSE_MIN_CONFIDENCE` and recommends `contain`. It never acts on heuristics alone.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # fill in, then: set -a; source .env; set +a
pytest -q               # offline tests, no Okta or Claude calls
python -m okta_ai_sentinel replay samples/events.json
```

### Option A: Real-time with an Okta Event Hook (recommended)

1. Deploy `python -m okta_ai_sentinel serve --port 8080` behind HTTPS.
2. In the Okta Admin Console go to **Workflow → Event Hooks → Create Event Hook**:
   - URL: `https://<your-host>/okta/events`
   - Authentication field `Authorization`, secret = `OKTA_EVENT_HOOK_SECRET`
   - Subscribe to events such as `user.session.start`, `user.authentication.sso`,
     `app.oauth2.as.token.grant.access_token`, `app.oauth2.as.authorize`,
     `system.api_token.create`, `user.lifecycle.*`, `group.user_membership.add`,
     `application.user_membership.add`, `user.account.privilege.grant`, `policy.evaluate_sign_on`.
3. Click **Verify**. The service answers Okta's one-time verification challenge.

### Option B: Poll the System Log

```bash
python -m okta_ai_sentinel poll --interval 60
```
This needs a token with `okta.logs.read`. Polling covers every System Log event type,
including types that Event Hooks can't deliver.

## Tuning

- Put sanctioned automation (SCIM bridges, Terraform, IGA tools) on `ALLOWLIST` by login,
  user id or OAuth client id.
- Set `CLAUDE_TRIAGE=false` to run on heuristics only (alerts at `FLAG_THRESHOLD`).
- Run `replay` on an export of a few days of your own System Log to check false positives
  before you turn on Slack or auto-response.

## Limits

- The Okta System Log records authentication, token, admin and lifecycle events. It does
  **not** record every read-only API GET. Detection covers what Okta logs.
- User agents can be spoofed. A careful agent that uses a browser user agent from a
  residential IP is caught only by its behavior (timing, enumeration, grant types) and by
  Claude's review of the timeline.
- Detector state is in-memory per process. Run a single instance, or move the history
  store to Redis to scale out.
