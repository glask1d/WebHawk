"""Leave a trail mark on a URL already in the shared list.

Marks live in marks.txt in the workspace. Adding one does not create a
scope file and does not fetch the URL. A URL that is not already listed
is refused.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from hawk.workspace import read_urls, workspace_dir

_LABEL = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_MARK = "blaze"
_TAG = "trail marks on the url list"
_ART = (
    r"              )",
    "             ) \\",
    r"            )   )",
    r"           ( blaze )",
    r"            )   )",
    r"             ) /",
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
        prog="webhawk blaze",
        description="Label a URL that is already in the shared list.",
    )
    parser.add_argument("--plain", action="store_true", help="Skip the banner.")
    sub = parser.add_subparsers(dest="command")
    listed = sub.add_parser("list", help="Print marks, or the URLs for one label.")
    listed.add_argument("label", nargs="?", help="Only this label.")
    added = sub.add_parser("add", help="Mark one listed URL.")
    added.add_argument("label", help="Short label, such as login or review.")
    added.add_argument("url", help="URL that is already in the shared list.")
    removed = sub.add_parser("remove", help="Remove one mark.")
    removed.add_argument("label")
    removed.add_argument("url")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.plain:
        _show_banner()
    if args.command == "add":
        return _add(args.label, args.url)
    if args.command == "remove":
        return _remove(args.label, args.url)
    if args.command == "list":
        return _list(args.label, plain=args.plain)
    return _list(None, plain=args.plain)


def marks_path():
    return workspace_dir() / "marks.txt"


def read_marks() -> list[tuple[str, str]]:
    path = marks_path()
    if not path.is_file():
        return []
    found: list[tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or " " not in line:
            continue
        label, url = line.split(" ", 1)
        label = label.strip().lower()
        url = url.strip()
        if label and url:
            found.append((label, url))
    return found


def format_banner(color: bool) -> str:
    return _banner(_ART, _MARK, _TAG, color)


def _add(label: str, url: str) -> int:
    name = _label(label)
    target = url.strip()
    if name is None:
        _say("A label is a short word, such as login.")
        return 2
    if not target or any(char in target for char in "\r\n"):
        _say("Give a single URL.")
        return 2
    if target not in read_urls():
        _say("That URL is not in the shared list.")
        return 2
    current = read_marks()
    if (name, target) in current:
        print(f"{name} already marks {target}")
        return 0
    current.append((name, target))
    _write(current)
    print(f"{name} marks {target}")
    return 0


def _remove(label: str, url: str) -> int:
    name = _label(label)
    target = url.strip()
    if name is None or not target:
        _say("Give a label and a URL.")
        return 2
    current = read_marks()
    kept = [item for item in current if item != (name, target)]
    if len(kept) == len(current):
        _say("That mark is not saved.")
        return 2
    _write(kept)
    print(f"{name} cleared {target}")
    return 0


def _list(label: str | None, *, plain: bool = False) -> int:
    name = None
    if label:
        name = _label(label)
        if name is None:
            _say("A label is a short word, such as login.")
            return 2
    current = read_marks()
    if name:
        urls = [url for item, url in current if item == name]
        if not urls:
            _say(f"no {name} marks")
            return 0
        for url in urls:
            print(url)
        return 0
    if not current:
        _say("no marks")
        return 0
    color = _color(sys.stdout) and not plain
    last = ""
    for item, url in current:
        if item != last:
            head = f"{_MAGENTA}{item}{_RESET}" if color else item
            print(head)
            last = item
        body = f"  {_WHITE}{url}{_RESET}" if color else f"  {url}"
        print(body)
    return 0


def _label(value: str) -> str | None:
    text = value.strip().lower()
    if _LABEL.fullmatch(text):
        return text
    return None


def _write(rows: list[tuple[str, str]]) -> None:
    path = marks_path()
    if not rows:
        if path.exists():
            path.unlink()
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# WebHawk marks. One label and one URL per line.", ""]
    lines.extend(f"{label} {url}" for label, url in rows)
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
