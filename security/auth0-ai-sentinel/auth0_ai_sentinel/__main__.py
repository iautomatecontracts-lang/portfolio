"""CLI.

  python -m auth0_ai_sentinel poll [--interval 60]
  python -m auth0_ai_sentinel replay logs.json
  python -m auth0_ai_sentinel serve [--port 8080]
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

from . import build_sentinel
from .config import load
from .logstream import parse_batch


def _poll(args: argparse.Namespace) -> None:
    sentinel = build_sentinel(load())
    if sentinel.auth0 is None:
        sys.exit("poll mode needs AUTH0_DOMAIN, AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET")
    seed = sentinel.auth0.latest_logs(100)
    for item in seed:
        sentinel.process(item)
    checkpoint = seed[-1]["log_id"] if seed else None
    logging.info("Polling Auth0 logs every %ss", args.interval)
    while True:
        time.sleep(args.interval)
        if checkpoint is None:
            seed = sentinel.auth0.latest_logs(100)
            checkpoint = seed[-1]["log_id"] if seed else None
            continue
        for item in sentinel.auth0.logs_after(checkpoint):
            sentinel.process(item)
            checkpoint = item["log_id"]


def _replay(args: argparse.Namespace) -> None:
    sentinel = build_sentinel(load())
    items = parse_batch(Path(args.file).read_bytes())
    flagged = sum(1 for item in items if sentinel.process(item))
    print(f"{flagged} alert(s) from {len(items)} log event(s)")


def _serve(args: argparse.Namespace) -> None:
    import uvicorn

    uvicorn.run("auth0_ai_sentinel.server:app", host=args.host, port=args.port)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    p = argparse.ArgumentParser(prog="auth0_ai_sentinel")
    sub = p.add_subparsers(dest="cmd", required=True)

    poll = sub.add_parser("poll", help="pull Auth0 tenant logs on an interval")
    poll.add_argument("--interval", type=int, default=60)
    poll.set_defaults(fn=_poll)

    rep = sub.add_parser("replay", help="score a file of Auth0 logs (offline)")
    rep.add_argument("file")
    rep.set_defaults(fn=_replay)

    srv = sub.add_parser("serve", help="receive an Auth0 Log Stream over HTTP")
    srv.add_argument("--host", default="0.0.0.0")
    srv.add_argument("--port", type=int, default=8080)
    srv.set_defaults(fn=_serve)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
