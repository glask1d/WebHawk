"""Follow redirects for one in-scope URL.

Each hop is one request. The next hop is not fetched when it leaves the
original hostname or when it is outside scope. The chain is stdout.
"""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urljoin, urlsplit

import httpx

from hawk.http import client
from hawk.workspace import allowed, explain_block, hostname_of

_REDIRECTS = {301, 302, 303, 307, 308}
_DEFAULT_LIMIT = 10
_MAX_LIMIT = 20


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk redirect",
        description="Follow redirects and stop when a hop leaves the host or scope.",
    )
    parser.add_argument("url", help="In-scope URL to start from.")
    parser.add_argument("--limit", type=int, default=_DEFAULT_LIMIT, help="Maximum hops. Default 10.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Seconds for each hop. Default 10.")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates.")
    parser.add_argument("--cookie", default=None, help="Cookie for this run. Replaces the saved session cookie.")
    parser.add_argument(
        "--authorization",
        default=None,
        help="Authorization for this run. Replaces the saved session value.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit < 1 or args.limit > _MAX_LIMIT or args.timeout <= 0:
        _say(f"Limit must be 1 through {_MAX_LIMIT}. Timeout must be greater than 0.")
        return 2
    start = args.url.strip()
    parts = urlsplit(start)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        _say("Give an http or https URL, such as http://127.0.0.1/.")
        return 2
    if not allowed(start):
        _say(explain_block(hostname_of(start) or start))
        return 2
    origin = parts.hostname.lower().rstrip(".")
    current = start
    try:
        with client(
            args.timeout,
            insecure=args.insecure,
            cookie=args.cookie,
            authorization=args.authorization,
        ) as http:
            for hop in range(args.limit):
                if not allowed(current):
                    _say(explain_block(hostname_of(current) or current))
                    return 2
                host = (hostname_of(current) or "").lower().rstrip(".")
                if host != origin:
                    _say(f"Stopped. {current} is not on {origin}.")
                    return 0
                try:
                    with http.stream("GET", current) as response:
                        status = response.status_code
                        location = response.headers.get("location", "").strip()
                except httpx.HTTPError as exc:
                    _say(f"Could not fetch {current}: {exc.__class__.__name__}")
                    return 1
                nxt = urljoin(current, location) if location else ""
                if status in _REDIRECTS and nxt:
                    print(f"{status} {current} -> {nxt}")
                    nxt_host = (hostname_of(nxt) or "").lower().rstrip(".")
                    if nxt_host != origin:
                        _say(f"Stopped. {nxt} is not on {origin}.")
                        return 0
                    if not allowed(nxt):
                        _say(explain_block(hostname_of(nxt) or nxt))
                        return 0
                    current = nxt
                    if hop + 1 >= args.limit:
                        _say(f"Stopped after {args.limit} hops.")
                        return 0
                    continue
                print(f"{status} {current}")
                return 0
    except httpx.HTTPError as exc:
        _say(f"Could not fetch {start}: {exc.__class__.__name__}")
        return 1
    return 0


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
