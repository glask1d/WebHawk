"""Save a Cookie or Authorization value for later requests.

This is a setting, not a scan. The values are whatever you already have.
They are stored in the workspace and sent by silk, forms, vhost, redirect,
and diff.
"""

from __future__ import annotations

import argparse

from hawk.session import load_session, session_path, write_session


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk session",
        description="Save a Cookie or Authorization header for in-scope requests.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("show", help="Print the saved headers.")
    setter = sub.add_parser("set", help="Save one header.")
    setter.add_argument("kind", choices=("cookie", "authorization"))
    setter.add_argument("value", nargs="+", help="The header value you already have.")
    clearer = sub.add_parser("clear", help="Remove one saved header, or both.")
    clearer.add_argument("kind", nargs="?", choices=("cookie", "authorization"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "show":
        return _show()
    if args.command == "set":
        value = " ".join(args.value).strip()
        if not value or "\n" in value or "\r" in value:
            print("Give a single header value.", flush=True)
            return 2
        current = load_session()
        current[args.kind] = value
        write_session(current)
        print(f"{args.kind} saved in {session_path()}")
        return 0
    if args.command == "clear":
        current = load_session()
        if args.kind:
            current.pop(args.kind, None)
        else:
            current.clear()
        write_session(current)
        print("session cleared" if not args.kind else f"{args.kind} cleared")
        return 0
    print("Unknown session command.")
    return 2


def _show() -> int:
    current = load_session()
    if not current:
        print("No session headers saved.")
        print("  webhawk session set cookie 'session=abc'")
        print("  webhawk session set authorization 'Bearer token'")
        return 0
    for key in ("cookie", "authorization"):
        if key in current:
            print(f"{key}: {current[key]}")
    return 0
