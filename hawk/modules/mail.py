"""Explain mail records for one in-scope name.

Reads MX and SPF from the name, DMARC from _dmarc, and DKIM only for
selectors you pass. Mail hosts are not resolved, and no selector is guessed.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from hawk.modules.dns import lookup, normalize_name, resolver_address, system_resolver
from hawk.workspace import allowed, explain_block

_MARK = "mail"
_TAG = "MX, SPF, DKIM, and DMARC for one name"
_ART = (
    r"    .-----------------.",
    "    |\\               /|",
    r"    | \    mail     / |",
    r"    |  \   (  )    /  |",
    r"    |   '---------'   |",
    r"    '-----------------'",
)
_CYAN = "\033[1;96m"
_YELLOW = "\033[1;93m"
_MAGENTA = "\033[1;95m"
_WHITE = "\033[1;97m"
_DIM = "\033[2;96m"
_RESET = "\033[0m"
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CLIP = 300


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk mail",
        description="Explain MX, SPF, DKIM, and DMARC for one in-scope name.",
    )
    parser.add_argument("name", help="Hostname to explain. A URL uses that URL's hostname.")
    parser.add_argument("--resolver", help="Resolver address. Default: the first system nameserver.")
    parser.add_argument("--port", type=int, default=53, help="Resolver port. Default 53.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Seconds to wait for each reply. Default 5.")
    parser.add_argument(
        "--selector",
        action="append",
        default=None,
        help="DKIM selector, such as s1. Repeat for another. None are guessed.",
    )
    parser.add_argument("--plain", action="store_true", help="Skip the banner.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0 or not 1 <= args.port <= 65535:
        _say("Timeout must be greater than 0, and the port must be 1 through 65535.")
        return 2
    name = normalize_name(args.name)
    if not name:
        _say("Give a hostname, such as app.internal.")
        return 2
    selectors = [item.strip().lower() for item in (args.selector or [])]
    if any(not _LABEL.fullmatch(item) for item in selectors):
        _say("A selector is one label, such as s1.")
        return 2
    if not allowed(name):
        _say(explain_block(name))
        return 2
    for extra in (f"_dmarc.{name}", *(f"{item}._domainkey.{name}" for item in selectors)):
        if not allowed(extra):
            _say(explain_block(extra))
            return 2
    if args.resolver:
        resolver = resolver_address(args.resolver)
        if not resolver:
            _say("Pass a resolver address, such as 127.0.0.1.")
            return 2
    else:
        resolver = system_resolver()
        if not resolver:
            _say("No resolver is set. Pass --resolver with an address.")
            return 1
    if not args.plain:
        _show_banner()
    try:
        found, notes, failed = lookup(name, resolver, args.port, args.timeout)
    except (OSError, ValueError) as exc:
        _say(f"Could not look up {name}: {exc.__class__.__name__}")
        return 1
    spf = _spf(found["TXT"])
    if failed and not found["MX"] and not spf:
        _say(f"{name} lookup failed.")
        return 1
    color = _color(sys.stdout) and not args.plain
    for value in found["MX"]:
        print(format_field("MX", _clip(value), color))
    if spf:
        print(format_field("SPF", _clip(spf), color))
    dmarc_records, dmarc_notes, dmarc_failed = _txt(f"_dmarc.{name}", resolver, args.port, args.timeout)
    policy = _prefixed(dmarc_records, "v=dmarc1")
    if policy:
        print(format_field("DMARC", _clip(policy), color))
    dkim_rows: list[tuple[str, str]] = []
    dkim_failed: list[str] = []
    dkim_notes: list[str] = []
    for selector in selectors:
        records, notes_for, selector_failed = _txt(
            f"{selector}._domainkey.{name}", resolver, args.port, args.timeout
        )
        dkim_notes.extend(notes_for)
        text = _prefixed(records, "v=dkim1")
        if selector_failed and not text:
            dkim_failed.append(selector)
            continue
        if text:
            summary = "key present" if _tag(text, "p") else _clip(text)
            dkim_rows.append((selector, summary))
        else:
            dkim_rows.append((selector, ""))
    for selector, summary in dkim_rows:
        if summary:
            print(format_field("DKIM", f"{selector}\t{summary}", color))
    for note in (
        *_kept(notes),
        *dmarc_notes,
        *dkim_notes,
        *review_notes(found["MX"], spf, policy, selectors, dkim_rows),
    ):
        _note(note)
    if dmarc_failed and not policy:
        _say("DMARC lookup failed.")
    for selector in dkim_failed:
        _say(f"DKIM lookup failed for {selector}.")
    return 0


def review_notes(
    mx: list[str],
    spf: str,
    dmarc: str,
    selectors: list[str],
    dkim: list[tuple[str, str]],
) -> list[str]:
    notes: list[str] = []
    if not mx:
        notes.append("review: no MX")
    if not spf:
        notes.append("review: no SPF")
    else:
        notes.extend(_spf_notes(spf))
    if not dmarc:
        notes.append("review: no DMARC")
    elif (_tag(dmarc, "p") or "none") == "none":
        notes.append("review: DMARC policy is none")
    if not selectors:
        notes.append("review: no DKIM selector was given")
    for selector, summary in dkim:
        if not summary:
            notes.append(f"review: no DKIM record for {selector}")
    return notes


def format_banner(color: bool) -> str:
    return _banner(_ART, _MARK, _TAG, color)


def format_field(key: str, value: str, color: bool) -> str:
    if not color:
        return f"{key}\t{value}"
    return f"  {_CYAN}{key:<12}{_RESET} {_WHITE}{value}{_RESET}"


def _txt(name: str, resolver: str, port: int, timeout: float) -> tuple[list[str], list[str], bool]:
    try:
        found, notes, failed = lookup(name, resolver, port, timeout)
    except (OSError, ValueError):
        return [], [], True
    return found["TXT"], _kept(notes), failed


def _prefixed(records: list[str], prefix: str) -> str:
    for value in records:
        if value.lower().startswith(prefix):
            return value
    return ""


def _spf(records: list[str]) -> str:
    return _prefixed(records, "v=spf1")


def _spf_notes(record: str) -> list[str]:
    quals: list[str] = []
    for term in record.split():
        item = term.lower().rstrip(";")
        body = item[1:] if item[:1] in "+-~?" else item
        if body == "all":
            quals.append(item[0] if item[:1] in "+-~?" else "+")
    if "+" in quals:
        return ["review: SPF allows any sender (+all)"]
    if "-" not in quals and "~" not in quals:
        return ["review: SPF does not use -all or ~all"]
    return []


def _tag(record: str, name: str) -> str:
    for part in record.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        if key.strip().lower() == name:
            return value.strip().lower()
    return ""


def _kept(notes: list[str]) -> list[str]:
    return [note for note in notes if note.startswith("The answer was truncated")]


def _clip(value: str) -> str:
    text = " ".join(value.split())
    if len(text) <= _CLIP:
        return text
    return text[: _CLIP - 1] + "…"


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


def _note(message: str) -> None:
    if _color(sys.stderr):
        message = f"{_YELLOW}{message}{_RESET}"
    print(message, file=sys.stderr, flush=True)
