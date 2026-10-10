"""Look over the engagement from one perch.

Prints scope entries, how many URLs and saved requests are on disk, and
whether a cookie or Authorization value is saved. The values stay hidden.
Hosts in the URL list that fall outside scope are listed at the bottom.
Nothing is contacted.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

from hawk.session import load_session
from hawk.workspace import allowed, hostname_of, read_entries, read_urls, requests_dir, scope_is_active

_MARK = "roost"
_TAG = "the perch above this engagement"
_ART = (
    r"            ___",
    r"         .-'   `-.",
    "        /   roost  \\",
    r"        |  (o) (o) |",
    "         \\    ^    /",
    r"          '-----'",
    r"         ===[ ]===",
)
_CYAN = "\033[1;96m"
_YELLOW = "\033[1;93m"
_MAGENTA = "\033[1;95m"
_WHITE = "\033[1;97m"
_DIM = "\033[2;96m"
_RESET = "\033[0m"


@dataclass(frozen=True)
class Report:
    entries: tuple[str, ...] | None
    urls: int
    requests: int
    cookie: bool
    authorization: bool
    outside: tuple[str, ...]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk roost",
        description="Show scope, counts, and URL hosts that fall outside scope.",
    )
    parser.add_argument("--plain", action="store_true", help="Skip the banner.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.plain:
        _show_banner()
    report = gather()
    color = _color(sys.stdout) and not args.plain
    sys.stdout.write(format_report(report, color))
    return 0


def gather() -> Report:
    entries = tuple(read_entries()) if scope_is_active() else None
    urls = read_urls()
    saved = load_session()
    return Report(
        entries=entries,
        urls=len(urls),
        requests=_request_count(),
        cookie="cookie" in saved,
        authorization="authorization" in saved,
        outside=tuple(_outside(urls)),
    )


def format_report(report: Report, color: bool) -> str:
    lines = [_heading("scope", color)]
    if report.entries is None:
        lines.append(_row("no scope file", color, warn=True))
    elif not report.entries:
        lines.append(_row("no entries", color))
    else:
        lines.extend(_row(entry, color) for entry in report.entries)
    lines.append(_pair("urls", str(report.urls), color))
    lines.append(_pair("requests", str(report.requests), color))
    cookie = "saved" if report.cookie else "empty"
    authorization = "saved" if report.authorization else "empty"
    lines.append(_pair("session", f"cookie {cookie}, authorization {authorization}", color))
    lines.append(_heading("outside", color))
    if report.outside:
        lines.extend(_row(host, color, warn=True) for host in report.outside)
    else:
        lines.append(_row("none", color))
    return "\n".join(lines) + "\n"


def format_banner(color: bool) -> str:
    return _banner(_ART, _MARK, _TAG, color)


def _outside(urls: list[str]) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for url in urls:
        host = hostname_of(url)
        if not host or host in seen:
            continue
        seen.add(host)
        if not allowed(host):
            found.append(host)
    return sorted(found)


def _request_count() -> int:
    root = requests_dir()
    if not root.is_dir():
        return 0
    return sum(1 for path in root.iterdir() if path.is_file())


def _heading(text: str, color: bool) -> str:
    if not color:
        return text
    return f"{_MAGENTA}{text}{_RESET}"


def _pair(key: str, value: str, color: bool) -> str:
    if not color:
        return f"{key}\t{value}"
    return f"  {_CYAN}{key:<12}{_RESET} {_WHITE}{value}{_RESET}"


def _row(text: str, color: bool, *, warn: bool = False) -> str:
    if not color:
        return f"  {text}"
    paint = _YELLOW if warn else _WHITE
    return f"  {paint}{text}{_RESET}"


def _banner(art: tuple[str, ...], mark: str, tag: str, color: bool) -> str:
    lines: list[str] = []
    for line in art:
        if not color:
            lines.append(line)
            continue
        if mark in line:
            left, _, right = line.partition(mark)
            lines.append(f"{_CYAN}{left}{_MAGENTA}{mark}{_CYAN}{right}{_RESET}")
            continue
        painted: list[str] = []
        for ch in line:
            if ch in "()[]":
                painted.append(f"{_YELLOW}{ch}{_CYAN}")
            else:
                painted.append(ch)
        lines.append(f"{_CYAN}{''.join(painted)}{_RESET}")
    lines.append(f"{_DIM}{tag}{_RESET}" if color else tag)
    return "\n".join(lines)


def _show_banner() -> None:
    if not _isatty(sys.stderr):
        return
    print(format_banner(_color(sys.stderr)), file=sys.stderr)
    print(file=sys.stderr)


def _color(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") in {"", "dumb"}:
        return False
    return _isatty(stream)


def _isatty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False
