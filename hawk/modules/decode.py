"""Print one page with non-image base64 shown as text.

A local file stays on disk. An http or https URL is one GET, and only when
that host is in scope. Image data and image bytes are left encoded. Other
blocks that decode as text are written in place.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from hawk.http import client, read_body
from hawk.workspace import allowed, explain_block, hostname_of

_MAX_BYTES = 1_000_000
_MAX_REDIRECTS = 3
_DEFAULT_MIN = 64
_REDIRECTS = {301, 302, 303, 307, 308}
_MARK = "decode"
_TAG = "page source, with non-image base64 written out as text"
_ART = (
    r"        .------.",
    r"      .'        '.",
    "     /   decode   \\",
    r"    |    (    )    |",
    "     \\   '----'   /",
    r"      '.        .'",
    r"        '------'",
)
_CYAN = "\033[1;96m"
_YELLOW = "\033[1;93m"
_MAGENTA = "\033[1;95m"
_GREEN = "\033[1;92m"
_RESET = "\033[0m"
_DATA = re.compile(
    r"data:([^,;\s]*)(?:;[^,;\s]+)*;base64,([A-Za-z0-9+/_\-\r\n]+=*)",
    re.IGNORECASE,
)
_CHUNK = re.compile(
    r"[A-Za-z0-9+/_-]{40,}={0,2}(?:[ \t\r\n]+[A-Za-z0-9+/_-]{4,}={0,2})*"
)
_CHARSET = re.compile(r"charset=[\"']?([A-Za-z0-9._:+-]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Unfolded:
    text: str
    decoded: int
    images: int


class ScopeStop(Exception):
    def __init__(self, host: str) -> None:
        super().__init__(host)
        self.host = host


class HostStop(Exception):
    def __init__(self, url: str, origin: str) -> None:
        super().__init__(url)
        self.url = url
        self.origin = origin


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk decode",
        description="Print one page with non-image base64 blocks shown as text.",
    )
    parser.add_argument("target", help="In-scope http(s) URL, or a local file.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Seconds for the request. Default 10.")
    parser.add_argument(
        "--min",
        type=int,
        default=_DEFAULT_MIN,
        help="Shortest unmarked base64 block to decode. Default 64. Data URIs are always considered.",
    )
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates.")
    parser.add_argument("--cookie", default=None, help="Cookie for this run. Replaces the saved session cookie.")
    parser.add_argument(
        "--authorization",
        default=None,
        help="Authorization for this run. Replaces the saved session value.",
    )
    parser.add_argument("--plain", action="store_true", help="Skip the banner and leave decoded text uncolored.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0 or args.min < 16:
        _say("Timeout must be greater than 0, and --min must be 16 or more.")
        return 2
    target = args.target.strip()
    path = Path(target)
    if path.is_file():
        if not args.plain:
            _show_banner()
        try:
            data = path.read_bytes()
        except OSError as exc:
            _say(f"Could not read {target}: {exc.__class__.__name__}")
            return 1
        truncated = len(data) > _MAX_BYTES
        text = _decode_body(data[:_MAX_BYTES], "")
        status = ""
    else:
        parts = urlsplit(target)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            _say("Give an http or https URL, or a file that exists.")
            return 2
        if not allowed(target):
            _say(explain_block(hostname_of(target) or target))
            return 2
        if not args.plain:
            _show_banner()
        try:
            with client(
                args.timeout,
                insecure=args.insecure,
                cookie=args.cookie,
                authorization=args.authorization,
            ) as http:
                body, content_type, final, truncated, status = fetch_page(http, target)
        except ScopeStop as exc:
            _say(explain_block(exc.host))
            return 2
        except HostStop as exc:
            _say(f"Stopped. {exc.url} leaves {exc.origin}.")
            return 0
        except httpx.HTTPError as exc:
            _say(f"Could not fetch {target}: {exc.__class__.__name__}")
            return 1
        except RuntimeError as exc:
            _say(str(exc))
            return 1
        text = _decode_body(body, content_type)
        _say(f"{status} {final}")
    color = _color(sys.stdout) and not args.plain
    unfolded = unfold(text, minimum=args.min, color=color)
    sys.stdout.write(unfolded.text)
    if not unfolded.text.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()
    if truncated:
        _say("The page was truncated.")
    _note(_summary(unfolded))
    return 0


def fetch_page(http: httpx.Client, url: str) -> tuple[bytes, str, str, bool, int]:
    """Return body, content type, final URL, truncated, and status."""
    origin = (hostname_of(url) or "").lower().rstrip(".")
    current = url
    for hop in range(_MAX_REDIRECTS + 1):
        if not allowed(current):
            raise ScopeStop(hostname_of(current) or current)
        host = (hostname_of(current) or "").lower().rstrip(".")
        if host != origin:
            raise HostStop(current, origin)
        with http.stream("GET", current) as response:
            status = response.status_code
            location = response.headers.get("location", "").strip()
            content_type = response.headers.get("content-type", "")
            if status in _REDIRECTS and location and hop < _MAX_REDIRECTS:
                read_body(response, 65_536)
                current = urljoin(current, location)
                continue
            body = read_body(response, _MAX_BYTES + 1)
        truncated = len(body) > _MAX_BYTES
        if status in _REDIRECTS and location:
            raise RuntimeError(f"Stopped after {_MAX_REDIRECTS} redirects.")
        return body[:_MAX_BYTES], content_type, current, truncated, status
    raise RuntimeError(f"Stopped after {_MAX_REDIRECTS} redirects.")


def unfold(text: str, *, minimum: int = _DEFAULT_MIN, color: bool = False) -> Unfolded:
    """Replace non-image base64 with the text it contains."""
    occupied: list[tuple[int, int]] = []
    changes: list[tuple[int, int, str]] = []
    images = 0
    for match in _DATA.finditer(text):
        occupied.append((match.start(), match.end()))
        payload = match.group(2)
        mime = match.group(1).lower()
        if mime.startswith("image/") or _is_image(payload):
            images += 1
            continue
        decoded = _as_text(_payload_bytes(payload))
        if decoded is None:
            continue
        changes.append((match.start(), match.end(), _paint(decoded, color)))
    for match in _CHUNK.finditer(text):
        if _overlaps(match.start(), match.end(), occupied):
            continue
        payload = match.group(0)
        compact = "".join(payload.split())
        if len(compact) < minimum:
            continue
        if _is_image(compact):
            images += 1
            continue
        decoded = _as_text(_payload_bytes(compact))
        if decoded is None:
            continue
        changes.append((match.start(), match.end(), _paint(decoded, color)))
    return Unfolded(_apply(text, changes), len(changes), images)


def format_banner(color: bool) -> str:
    lines: list[str] = []
    for line in _ART:
        if not color:
            lines.append(line)
            continue
        if _MARK in line:
            left, _, right = line.partition(_MARK)
            lines.append(f"{_CYAN}{left}{_MAGENTA}{_MARK}{_CYAN}{right}{_RESET}")
            continue
        painted: list[str] = []
        for ch in line:
            if ch in "()[]":
                painted.append(f"{_YELLOW}{ch}{_CYAN}")
            else:
                painted.append(ch)
        lines.append(f"{_CYAN}{''.join(painted)}{_RESET}")
    lines.append(f"{_CYAN}{_TAG}{_RESET}" if color else _TAG)
    return "\n".join(lines)


def _apply(text: str, changes: list[tuple[int, int, str]]) -> str:
    pieces: list[str] = []
    cursor = len(text)
    for start, end, replacement in sorted(changes, reverse=True):
        pieces.append(text[end:cursor])
        pieces.append(replacement)
        cursor = start
    pieces.append(text[:cursor])
    return "".join(reversed(pieces))


def _payload_bytes(payload: str) -> bytes | None:
    compact = "".join(payload.split())
    if not compact or len(compact) % 4 == 1:
        return None
    if any(char in compact for char in "+/") and any(char in compact for char in "-_"):
        return None
    padded = compact + ("=" * (-len(compact) % 4))
    decoder = base64.urlsafe_b64decode if any(char in compact for char in "-_") else base64.b64decode
    try:
        return decoder(padded)
    except (ValueError, binascii.Error):
        return None


def _is_image(payload: str) -> bool:
    blob = _payload_bytes(payload)
    if not blob:
        return False
    if blob.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")):
        return True
    if len(blob) >= 12 and blob.startswith(b"RIFF") and blob[8:12] == b"WEBP":
        return True
    if len(blob) >= 8 and blob.startswith((b"\x00\x00\x01\x00", b"\x00\x00\x02\x00")):
        return True
    if len(blob) >= 14 and blob.startswith(b"BM") and blob[6:10] == b"\x00\x00\x00\x00":
        return True
    return False


def _as_text(blob: bytes | None) -> str | None:
    if not blob or b"\x00" in blob:
        return None
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip():
        return None
    visible = sum(1 for char in text if char in "\t\n\r" or char.isprintable())
    if visible / len(text) < 0.9:
        return None
    return text


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < stop and end > begin for begin, stop in spans)


def _paint(value: str, color: bool) -> str:
    if not color:
        return value
    return f"{_GREEN}{value}{_RESET}"


def _decode_body(body: bytes, content_type: str) -> str:
    match = _CHARSET.search(content_type)
    charset = match.group(1) if match else "utf-8"
    try:
        return body.decode(charset, "replace")
    except LookupError:
        return body.decode("utf-8", "replace")


def _summary(unfolded: Unfolded) -> str:
    text = f"decoded {unfolded.decoded} block(s)"
    if unfolded.images:
        text += f", left {unfolded.images} image block(s) encoded"
    return text


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
        message = f"{_GREEN}{message}{_RESET}"
    print(message, file=sys.stderr, flush=True)
