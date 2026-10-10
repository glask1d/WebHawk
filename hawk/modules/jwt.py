"""Decode a token you already have.

Prints the header and the claims. The signature is reported as present or
absent and is not checked. Nothing is sent on the network.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone

from hawk.session import load_session

_MARK = "jwt"
_TAG = "header and claims, with the signature left unchecked"
_ART = (
    r"          .----.",
    "         /  ()  \\",
    r"        |  jwt  |",
    "         \\  ||  /",
    r"          '----'",
    r"            ||",
    r"          [key]",
)
_CYAN = "\033[1;96m"
_YELLOW = "\033[1;93m"
_MAGENTA = "\033[1;95m"
_WHITE = "\033[1;97m"
_DIM = "\033[2;96m"
_RESET = "\033[0m"
_HEADER_FIRST = ("alg", "typ")
_CLAIM_FIRST = ("exp", "nbf", "iat", "iss", "sub", "aud")
_TIMES = {"exp", "nbf", "iat"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk jwt",
        description="Decode a token you already have. The signature is not checked.",
    )
    parser.add_argument("token", nargs="?", help="Token with a header, payload, and signature.")
    parser.add_argument(
        "--session",
        action="store_true",
        help="Decode the saved Authorization value. A positional token wins.",
    )
    parser.add_argument("--plain", action="store_true", help="Skip the banner.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    token = (args.token or "").strip()
    if not token and args.session:
        token = _session_token()
        if not token:
            _say("No Authorization value is saved.")
            return 2
    if not token:
        _say("Give a token, or pass --session.")
        return 2
    if not args.plain:
        _show_banner()
    try:
        header, payload, signed = decode_token(token)
    except ValueError as exc:
        _say(str(exc))
        return 2
    color = _color(sys.stdout) and not args.plain
    for key, value in header_rows(header):
        print(format_field(key, value, color))
    for key, value in claim_rows(payload):
        print(format_field(key, value, color))
    signature = "present, not checked" if signed else "absent"
    print(format_field("signature", signature, color, dim=True))
    for note in review_notes(header, payload):
        _note(note)
    return 0


def decode_token(token: str) -> tuple[dict, dict, bool]:
    """Return header, payload, and whether a signature segment is present."""
    parts = token.strip().split(".")
    if any(part != part.strip() or any(ch.isspace() for ch in part) for part in parts):
        raise ValueError("A token has three parts.")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise ValueError("A token has three parts.")
    try:
        header = json.loads(_b64(parts[0]))
        payload = json.loads(_b64(parts[1]))
    except (ValueError, json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("The token could not be decoded.") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("The token header and payload must be objects.")
    return header, payload, bool(parts[2])


def header_rows(header: dict) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key in _HEADER_FIRST:
        if key in header:
            rows.append((key, show_value(key, header[key])))
            seen.add(key)
    for key, value in header.items():
        if key not in seen:
            rows.append((str(key), show_value(str(key), value)))
    return rows


def claim_rows(payload: dict) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key in _CLAIM_FIRST:
        if key in payload:
            rows.append((key, show_value(key, payload[key])))
            seen.add(key)
    for key, value in payload.items():
        if key not in seen:
            rows.append((str(key), show_value(str(key), value)))
    return rows


def review_notes(header: dict, payload: dict) -> list[str]:
    notes: list[str] = []
    if str(header.get("alg", "")).strip().lower() == "none":
        notes.append("review: algorithm is none")
    if "exp" not in payload:
        notes.append("review: no exp")
    else:
        exp = _timestamp(payload.get("exp"))
        if exp is not None and exp < datetime.now(timezone.utc):
            notes.append("review: exp is in the past")
    nbf = _timestamp(payload.get("nbf")) if "nbf" in payload else None
    if nbf is not None and nbf > datetime.now(timezone.utc):
        notes.append("review: nbf is in the future")
    return notes


def show_value(key: str, value: object) -> str:
    if key in _TIMES:
        when = _timestamp(value)
        if when is not None:
            return when.strftime("%Y-%m-%d %H:%M:%SZ")
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=True)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def format_banner(color: bool) -> str:
    return _banner(_ART, _MARK, _TAG, color)


def format_field(key: str, value: str, color: bool, *, dim: bool = False) -> str:
    if not color:
        return f"{key}\t{value}"
    paint = _DIM if dim else _WHITE
    return f"  {_CYAN}{key:<12}{_RESET} {paint}{value}{_RESET}"


def _session_token() -> str:
    saved = load_session().get("authorization", "").strip()
    if saved.lower().startswith("bearer "):
        return saved[7:].strip()
    return saved


def _b64(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _timestamp(value: object) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(int(value), timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


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
