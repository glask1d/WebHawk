"""Keep a timestamped field pad next to the scope file.

Notes live in notes.txt. Writing one does not create a scope file and
does not contact a host.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

from hawk.workspace import workspace_dir

_MARK = "quill"
_TAG = "field notes beside the scope"
_ART = (
    r"               /",
    r"              /",
    r"             /",
    "            / \\",
    r"           | quill |",
    r"            \   /",
    r"             [_]",
)
_CYAN = "\033[1;96m"
_YELLOW = "\033[1;93m"
_MAGENTA = "\033[1;95m"
_WHITE = "\033[1;97m"
_DIM = "\033[2;96m"
_RESET = "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk quill",
        description="Keep a timestamped note pad in the workspace.",
    )
    parser.add_argument("--plain", action="store_true", help="Skip the banner.")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="Print the pad.")
    added = sub.add_parser("add", help="Append one note.")
    added.add_argument("text", nargs="+", help="The note. One line.")
    sub.add_parser("clear", help="Remove the pad.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.plain:
        _show_banner()
    if args.command == "add":
        return _add(" ".join(args.text), plain=args.plain)
    if args.command == "clear":
        return _clear()
    return _list(plain=args.plain)


def notes_path():
    return workspace_dir() / "notes.txt"


def read_notes() -> list[tuple[str, str]]:
    path = notes_path()
    if not path.is_file():
        return []
    found: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or len(line) < 22 or line[20] != " ":
            continue
        stamp, text = line[:20], line[21:]
        if text:
            found.append((stamp, text))
    return found


def format_banner(color: bool) -> str:
    return _banner(_ART, _MARK, _TAG, color)


def format_note(stamp: str, text: str, color: bool) -> str:
    if not color:
        return f"{stamp}  {text}"
    return f"  {_DIM}{stamp}{_RESET}  {_WHITE}{text}{_RESET}"


def _add(text: str, *, plain: bool = False) -> int:
    note = " ".join(text.split())
    if not note or any(char in text for char in "\r\n"):
        _say("Give a single line.")
        return 2
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    rows = read_notes()
    rows.append((stamp, note))
    _write(rows)
    print(format_note(stamp, note, _color(sys.stdout) and not plain))
    return 0


def _list(*, plain: bool = False) -> int:
    rows = read_notes()
    if not rows:
        _say("no notes")
        return 0
    color = _color(sys.stdout) and not plain
    for stamp, text in rows:
        print(format_note(stamp, text, color))
    return 0


def _clear() -> int:
    path = notes_path()
    if path.exists():
        path.unlink()
    print("notes cleared")
    return 0


def _write(rows: list[tuple[str, str]]) -> None:
    path = notes_path()
    if not rows:
        if path.exists():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# WebHawk notes. One timestamped line each.", ""]
    lines.extend(f"{stamp} {text}" for stamp, text in rows)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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
