"""Compare two responses.

Each side is a saved file or one in-scope URL. A file stays local. A URL is
one GET, and only when that host is in scope. The report lists status,
headers, and a text diff of the bodies.
"""

from __future__ import annotations

import argparse
import difflib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from hawk.http import client, read_body
from hawk.workspace import allowed, explain_block, hostname_of, responses_dir

_MAX_BYTES = 200_000
_SKIP_HEADERS = {"date"}


@dataclass
class Side:
    label: str
    status: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    truncated: bool = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk diff",
        description="Compare two saved responses, or two in-scope URLs.",
    )
    parser.add_argument("left", help="Response file, a name in responses/, or an http(s) URL.")
    parser.add_argument("right", help="Response file, a name in responses/, or an http(s) URL.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Seconds for each fetch. Default 10.")
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
    if args.timeout <= 0:
        _say("Timeout must be greater than 0.")
        return 2
    urls = [item for item in (args.left, args.right) if _http_url(item) and not Path(item).is_file()]
    for url in urls:
        if not allowed(url):
            _say(explain_block(hostname_of(url) or url))
            return 2
    http = None
    try:
        if urls:
            http = client(
                args.timeout,
                insecure=args.insecure,
                cookie=args.cookie,
                authorization=args.authorization,
            )
        left = load_side(args.left, http)
        right = load_side(args.right, http)
    except FileNotFoundError as exc:
        _say(str(exc))
        return 2
    except httpx.HTTPError as exc:
        _say(f"Could not fetch: {exc.__class__.__name__}")
        return 1
    finally:
        if http is not None:
            http.close()
    print(render_diff(left, right), end="")
    return 0


def load_side(value: str, http: httpx.Client | None) -> Side:
    path = _resolve_saved(value)
    if path is not None:
        data = path.read_bytes()
        status, headers, body, truncated = parse_saved(data)
        return Side(value, status, headers, body, truncated)
    if _http_url(value):
        if http is None:
            raise FileNotFoundError(f"No file named {value}.")
        with http.stream("GET", value) as response:
            raw = read_body(response, _MAX_BYTES + 1)
            truncated = len(raw) > _MAX_BYTES
            body = raw[:_MAX_BYTES].decode("utf-8", errors="replace")
            headers = {key.lower(): value for key, value in response.headers.items()}
            return Side(value, str(response.status_code), headers, body, truncated)
    raise FileNotFoundError(f"No file named {value}.")


def _resolve_saved(value: str) -> Path | None:
    """A real file, or a bare name saved under responses/."""
    direct = Path(value)
    if direct.is_file():
        return direct
    if _bare_name(value):
        saved = responses_dir() / value
        if saved.is_file():
            return saved
    return None


def _bare_name(value: str) -> bool:
    if not value or value in {".", ".."} or "/" in value or "\\" in value:
        return False
    return Path(value).name == value


def parse_saved(data: bytes) -> tuple[str, dict[str, str], str, bool]:
    truncated = len(data) > _MAX_BYTES
    text = data[:_MAX_BYTES].decode("utf-8", errors="replace")
    normalized = text.replace("\r\n", "\n")
    if "\n\n" not in normalized:
        return "", {}, text, truncated
    head, body = normalized.split("\n\n", 1)
    lines = head.split("\n")
    status = ""
    first = lines[0].strip()
    if first.upper().startswith("HTTP/"):
        parts = first.split()
        status = parts[1] if len(parts) > 1 else first
    elif " HTTP/" in first.upper():
        status = first
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().lower()
        value = value.strip()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    return status, headers, body, truncated


def render_diff(left: Side, right: Side) -> str:
    lines: list[str] = []
    if left.status == right.status:
        lines.append(f"status: {left.status or '(none)'}")
    else:
        lines.append(f"status: {left.status or '(none)'} -> {right.status or '(none)'}")
    keys = sorted(set(left.headers) | set(right.headers))
    for key in keys:
        if key in _SKIP_HEADERS:
            continue
        before = left.headers.get(key)
        after = right.headers.get(key)
        if before == after:
            continue
        if before is None:
            lines.append(f"header {key}: added {after}")
        elif after is None:
            lines.append(f"header {key}: removed {before}")
        else:
            lines.append(f"header {key}: {before} -> {after}")
    if left.truncated or right.truncated:
        lines.append(f"body compared at the first {_MAX_BYTES} bytes")
    if left.body == right.body:
        lines.append("body: unchanged")
        lines.append("")
        return "\n".join(lines)
    if _binary(left.body) or _binary(right.body):
        lines.append(f"body: {len(left.body)} bytes -> {len(right.body)} bytes")
        lines.append("")
        return "\n".join(lines)
    diff = difflib.unified_diff(
        left.body.splitlines(keepends=True),
        right.body.splitlines(keepends=True),
        fromfile=left.label,
        tofile=right.label,
    )
    lines.append("body:")
    lines.extend(line.rstrip("\n") for line in diff)
    lines.append("")
    return "\n".join(lines)


def _http_url(value: str) -> bool:
    parts = urlsplit(value.strip()) if "://" in value else None
    return bool(parts and parts.scheme in {"http", "https"} and parts.hostname)


def _binary(text: str) -> bool:
    return "\x00" in text


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
