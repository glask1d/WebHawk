"""List the requests held in the workspace.

Each file in requests/ is one row: method, host, path, and whether that
host is in scope. `show` prints one file with Cookie and Authorization
blanked. Nothing is sent.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from hawk.modules.repeater import endpoint, parse_raw, path_and_query
from hawk.workspace import allowed, requests_dir

_MAX_BYTES = 1_000_000
_SECRET = {"cookie", "authorization", "proxy-authorization"}
_MARK = "clutch"
_TAG = "requests held in the talons"
_ART = (
    "            \\\\   //",
    "             \\\\ //",
    "              \\V/",
    r"          .--------.",
    r"          | clutch |",
    r"          '--------'",
    r"            [held]",
)
_CYAN = "\033[1;96m"
_YELLOW = "\033[1;93m"
_MAGENTA = "\033[1;95m"
_WHITE = "\033[1;97m"
_DIM = "\033[2;96m"
_RESET = "\033[0m"


@dataclass(frozen=True)
class Held:
    name: str
    method: str
    host: str
    path: str
    scope: str


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk clutch",
        description="List saved requests. Show one with Cookie and Authorization blanked.",
    )
    parser.add_argument("--plain", action="store_true", help="Skip the banner.")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="List saved requests.")
    show = sub.add_parser("show", help="Print one saved request with secrets blanked.")
    show.add_argument("name", help="File name inside the requests directory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.plain:
        _show_banner()
    if args.command == "show":
        return _show(args.name)
    rows = list_requests()
    color = _color(sys.stdout) and not args.plain
    if not rows:
        _say("no saved requests")
        _say("snare writes requests/example.com-snare-0001.http while it listens.")
        _say("clutch show <name> prints one.")
        return 0
    for row in rows:
        print(format_row(row, color))
    _say(f"{len(rows)} saved request(s)")
    _say("clutch show <name> prints one.")
    return 0


def list_requests() -> list[Held]:
    root = requests_dir()
    if not root.is_dir():
        return []
    rows: list[Held] = []
    for path in sorted(root.iterdir(), key=lambda item: item.name.lower()):
        if path.is_file():
            rows.append(_held(path))
    return rows


def redact(data: bytes) -> str:
    """Return the request with Cookie and Authorization values removed."""
    req = parse_raw(data)
    lines = [f"{req.method} {req.target} {req.version}"]
    for name, value in req.headers:
        if name.lower() in _SECRET:
            lines.append(f"{name}: [blank]")
        else:
            lines.append(f"{name}: {value}")
    text = "\r\n".join(lines) + "\r\n\r\n"
    return text + req.body.decode("latin-1", "replace")


def format_banner(color: bool) -> str:
    return _banner(_ART, _MARK, _TAG, color)


def format_row(row: Held, color: bool) -> str:
    plain = f"{row.name}\t{row.method}\t{row.host}\t{row.path}\t{row.scope}"
    if not color:
        return plain
    scope = f"{_YELLOW}{row.scope}{_RESET}" if row.scope != "in scope" else f"{_WHITE}{row.scope}{_RESET}"
    return f"  {_CYAN}{row.method:<6}{_RESET} {_WHITE}{row.host} {row.path}{_RESET}  {scope}  {_DIM}{row.name}{_RESET}"


def _show(name: str) -> int:
    path = _safe_path(name)
    if path is None:
        _say("Give the file name inside the requests directory.")
        return 2
    if not path.is_file():
        _say(f"No saved request named {Path(name).name}.")
        return 2
    if path.stat().st_size > _MAX_BYTES:
        _say(f"{path.name} is larger than {_MAX_BYTES} bytes.")
        return 2
    try:
        text = redact(path.read_bytes())
    except (OSError, ValueError) as exc:
        _say(str(exc) if isinstance(exc, ValueError) else f"Could not read {path.name}.")
        return 1
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")
    _say(f"Saved request {path.name}. repeater can send that file again.")
    return 0


def _held(path: Path) -> Held:
    if path.stat().st_size > _MAX_BYTES:
        return Held(path.name, "?", "?", "?", "too large")
    try:
        req = parse_raw(path.read_bytes())
    except (OSError, ValueError):
        return Held(path.name, "?", "?", "?", "unreadable")
    host, _port = endpoint(req, None)
    host = host.lower().rstrip(".")
    if not host:
        return Held(path.name, req.method, "-", path_and_query(req), "no host")
    scope = "in scope" if allowed(host) else "outside"
    return Held(path.name, req.method, host, path_and_query(req), scope)


def _safe_path(name: str) -> Path | None:
    if not name or name != Path(name).name or name in {".", ".."}:
        return None
    return requests_dir() / name


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


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
