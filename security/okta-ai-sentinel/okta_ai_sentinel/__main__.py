"""CLI.

  python -m okta_ai_sentinel poll [--interval 60] [--lookback 15]
  python -m okta_ai_sentinel replay events.json
  python -m okta_ai_sentinel serve [--port 8080]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime, timedelta, timezone

from . import build_sentinel
from .config import load


def _poll(args: argparse.Namespace) -> None:
    settings = load()
    sentinel = build_sentinel(settings)
    if sentinel.okta is None:
        sys.exit("poll mode needs OKTA_ORG_URL and OKTA_API_TOKEN")
    since = datetime.now(timezone.utc) - timedelta(minutes=args.lookback)
    logging.info("Polling %s System Log every %ss", settings.okta_org_url, args.interval)
    while True:
        last = since
        for event in sentinel.okta.iter_logs(since=since):
            sentinel.process(event)
            if ts := event.get("published"):
                last = max(last, datetime.fromisoformat(ts.replace("Z", "+00:00")))
        since = last  # overlap is fine: the detector de-duplicates by event uuid
        time.sleep(args.interval)


def _replay(args: argparse.Namespace) -> None:
    sentinel = build_sentinel(load())
    with open(args.file) as f:
        data = json.load(f)
    events = data.get("data", {}).get("events", []) if isinstance(data, dict) else data
    flagged = sum(1 for e in events if sentinel.process(e))
    print(f"{flagged} alert(s) from {len(events)} event(s)")


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    uvicorn.run("okta_ai_sentinel.server:app", host=args.host, port=args.port)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    p = argparse.ArgumentParser(prog="okta_ai_sentinel")
    sub = p.add_subparsers(dest="cmd", required=True)

    poll = sub.add_parser("poll", help="pull the Okta System Log on an interval")
    poll.add_argument("--interval", type=int, default=60)
    poll.add_argument("--lookback", type=int, default=15, help="minutes of history on start")
    poll.set_defaults(fn=_poll)

    rep = sub.add_parser("replay", help="score a JSON file of Okta events (offline)")
    rep.add_argument("file")
    rep.set_defaults(fn=_replay)

    srv = sub.add_parser("serve", help="receive Okta Event Hooks over HTTP")
    srv.add_argument("--host", default="0.0.0.0")
    srv.add_argument("--port", type=int, default=8080)
    srv.set_defaults(fn=_serve)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
