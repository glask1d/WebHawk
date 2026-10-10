"""Compare Host names on one address.

The connection goes to the URL you pass. Each name is sent once in the Host
header. Names are the ones you list, or the hostnames already in scope.
When a scope file exists, a name outside that scope is skipped.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

from hawk.http import client, read_body
from hawk.workspace import allowed, explain_block, hostname_of, read_entries, scope_is_active

_MAX_BYTES = 1_000_000
_DEFAULT_LIMIT = 50
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk vhost",
        description="Request one in-scope address once per Host name. Prints status, size, and title.",
    )
    parser.add_argument("url", help="Address to connect to, such as http://127.0.0.1:8080/.")
    parser.add_argument("names", nargs="*", help="Host names. With none, hostnames from the scope file are used.")
    parser.add_argument("--names", dest="names_file", help="File of host names, one per line.")
    parser.add_argument("--limit", type=int, default=_DEFAULT_LIMIT, help="Maximum names to request. Default 50.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Seconds for each request. Default 10.")
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
    if args.limit < 1 or args.timeout <= 0:
        _say("Limit and timeout must be greater than 0.")
        return 2
    target = canonical_target(args.url)
    if target is None:
        _say("Give an http or https URL, such as http://127.0.0.1:8080/.")
        return 2
    if not allowed(target):
        _say(explain_block(hostname_of(target) or target))
        return 2
    try:
        names = collect_names(args.names, args.names_file)
    except OSError as exc:
        _say(f"Could not read names: {exc}")
        return 1
    if not names:
        _say("Pass host names, or add hostnames with webhawk scope add.")
        return 2
    parts = urlsplit(target)
    baseline = parts.hostname or ""
    ordered = _unique([baseline, *names])
    scope_on = scope_is_active()
    chosen: list[str] = []
    skipped = 0
    for name in ordered:
        if scope_on and not allowed(name):
            skipped += 1
            continue
        chosen.append(name)
        if len(chosen) >= args.limit:
            break
    if not chosen:
        _say(explain_block(names[0]))
        return 2
    stopped = len(ordered) - skipped > args.limit
    print("host\tstatus\tbytes\ttitle")
    failures = 0
    try:
        with client(
            args.timeout,
            insecure=args.insecure,
            cookie=args.cookie,
            authorization=args.authorization,
        ) as http:
            for name in chosen:
                header = host_header(name, parts.port, parts.scheme)
                try:
                    status, size, title = fetch_one(http, target, header)
                except httpx.HTTPError as exc:
                    failures += 1
                    print(f"{header}\terror\t0\t{exc.__class__.__name__}")
                    continue
                print(f"{header}\t{status}\t{size}\t{title}")
    except httpx.HTTPError as exc:
        _say(f"Could not connect: {exc.__class__.__name__}")
        return 1
    if skipped:
        _say(f"{skipped} name(s) outside scope")
    if stopped:
        _say(f"Stopped after {args.limit} names.")
    if failures and failures == len(chosen):
        return 1
    return 0


def canonical_target(value: str) -> str | None:
    text = value.strip()
    if "://" not in text:
        text = "http://" + text
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    default = 443 if parts.scheme == "https" else 80
    netloc = host if parts.port in (None, default) else f"{host}:{parts.port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme, netloc, path, parts.query, ""))


def collect_names(words: list[str], file_name: str | None) -> list[str]:
    found = list(words)
    if file_name:
        for raw in Path(file_name).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                found.append(line)
    if found:
        return _unique(found)
    return _unique(name for name in read_entries() if _scope_hostname(name))


def host_header(name: str, port: int | None, scheme: str) -> str:
    text = name.strip().rstrip(".")
    default = 443 if scheme == "https" else 80
    if port and port != default and ":" not in text:
        return f"{text}:{port}"
    return text


def fetch_one(http: httpx.Client, url: str, host: str) -> tuple[int, int, str]:
    with http.stream("GET", url, headers={"Host": host}) as response:
        body = read_body(response, _MAX_BYTES)
        title = page_title(body.decode("utf-8", errors="replace"))
        return response.status_code, len(body), title


def page_title(text: str) -> str:
    match = _TITLE.search(text)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title.replace("\t", " ")[:80]


def _scope_hostname(entry: str) -> bool:
    if entry.startswith("*.") or "/" in entry:
        return False
    try:
        ipaddress.ip_address(entry)
    except ValueError:
        return True
    return False


def _unique(names) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for name in names:
        key = name.strip().rstrip(".").lower()
        if not key or key in seen:
            continue
        seen.add(key)
        ordered.append(name.strip().rstrip("."))
    return ordered


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
