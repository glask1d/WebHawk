"""Read the registry record for one in-scope domain.

Prints the registrar, creation date, expiry, and nameservers. With
--server, that address is the only host contacted. Without it, the IANA
whois server is asked for one referral, and that registry is queried once.
A second referral is ignored.
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import sys
from datetime import datetime, timedelta, timezone

from hawk.modules.dns import normalize_name, resolver_address
from hawk.workspace import allowed, explain_block

_IANA = "whois.iana.org"
_MAX_BYTES = 65536
_MARK = "whois"
_TAG = "registrar, dates, and nameservers for one domain"
_ART = (
    r"     ________________",
    r"   .'_(            )_'.",
    r"   |    registrar    |",
    r"   |     (whois)     |",
    r"   '-----------------'",
)
_CYAN = "\033[1;96m"
_YELLOW = "\033[1;93m"
_MAGENTA = "\033[1;95m"
_WHITE = "\033[1;97m"
_DIM = "\033[2;96m"
_RESET = "\033[0m"
_CREATED = ("creation date", "created")
_EXPIRES = ("registry expiry date", "expiry date", "expiration date", "expires")
_SERVERS = ("name server", "nserver")
_DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%Y%m%d")
_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk whois",
        description="Look up registrar, dates, and nameservers for one in-scope domain.",
    )
    parser.add_argument("name", help="Domain to look up. A URL uses that URL's hostname.")
    parser.add_argument("--server", help="Whois server address. Skips the IANA referral.")
    parser.add_argument("--port", type=int, default=43, help="Whois port. Default 43.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Seconds to wait. Default 10.")
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
    if not allowed(name):
        _say(explain_block(name))
        return 2
    server = None
    if args.server:
        server = resolver_address(args.server)
        if not server:
            _say("Pass a server address, such as 127.0.0.1.")
            return 2
    if not args.plain:
        _show_banner()
    try:
        text, notes = fetch_record(name, server, args.port, args.timeout)
    except RegistryError as exc:
        _say(str(exc))
        return 1
    except OSError as exc:
        target = server or _IANA
        _say(f"Could not query {target}: {exc.__class__.__name__}")
        return 1
    record = parse_record(text)
    color = _color(sys.stdout) and not args.plain
    rows = record_rows(name, record)
    for key, value in rows:
        print(format_field(key, value, color))
    for note in (*notes, *review_notes(record)):
        _note(note)
    if len(rows) == 1:
        _say("no registrar record")
    return 0


def fetch_record(
    name: str, server: str | None, port: int, timeout: float
) -> tuple[str, list[str]]:
    """Return the registry text. `server` skips the referral."""
    notes: list[str] = []
    if server:
        text, cut = _fetch(server, port, name, timeout)
    else:
        iana, _cut = _fetch(_IANA, port, name, timeout)
        refer = referral_host(iana)
        if not refer:
            raise RegistryError("The registry was not named.")
        text, cut = _fetch(refer, port, name, timeout)
    if cut:
        notes.append("The reply was truncated.")
    return text, notes


def referral_host(text: str) -> str | None:
    """First refer hostname. An address or a second refer is not used."""
    for key, value in pairs(text):
        if key != "refer":
            continue
        host = value.split()[0].strip().lower().rstrip(".")
        if _HOST.fullmatch(host):
            return host
        return None
    return None


def parse_record(text: str) -> dict[str, object]:
    found: dict[str, list[str]] = {}
    for key, value in pairs(text):
        found.setdefault(key, []).append(value)
    created_raw = _first(found, _CREATED)
    expires_raw = _first(found, _EXPIRES)
    names: list[str] = []
    for key in _SERVERS:
        for value in found.get(key, []):
            host = value.split()[0].strip().lower().rstrip(".")
            if host and host not in names:
                names.append(host)
    return {
        "registrar": _first(found, ("registrar", "sponsoring registrar")),
        "created": parse_when(created_raw) if created_raw else None,
        "created_text": created_raw,
        "expires": parse_when(expires_raw) if expires_raw else None,
        "expires_text": expires_raw,
        "nameservers": names,
    }


def record_rows(name: str, record: dict[str, object]) -> list[tuple[str, str]]:
    rows = [("domain", name)]
    registrar = record.get("registrar")
    if isinstance(registrar, str) and registrar:
        rows.append(("registrar", registrar))
    created = _when_text(record.get("created"), record.get("created_text"))
    if created:
        rows.append(("created", created))
    expires = _when_text(record.get("expires"), record.get("expires_text"))
    if expires:
        rows.append(("expires", expires))
    names = record.get("nameservers")
    if isinstance(names, list):
        rows.extend(("nserver", host) for host in names)
    return rows


def review_notes(record: dict[str, object]) -> list[str]:
    expires = record.get("expires")
    if not isinstance(expires, datetime):
        return []
    now = datetime.now(timezone.utc)
    shown = expires.strftime("%Y-%m-%d %H:%M:%SZ")
    if expires < now:
        return [f"review: expired on {shown}"]
    if expires - now <= timedelta(days=30):
        return [f"review: expires within 30 days ({shown})"]
    return []


def parse_when(value: str) -> datetime | None:
    text = value.strip()
    text = re.sub(r"(?i)\s*(utc|gmt)$", "", text).strip()
    text = re.sub(r"(\d{2}:\d{2}:\d{2})\.\d+", r"\1", text)
    text = text.replace("T", " ")
    if text.endswith("Z"):
        text = text[:-1].strip()
    text = re.sub(r"\s*[+-]\d{2}:?\d{2}$", "", text).strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def pairs(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "%#" or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = " ".join(key.strip().lower().split())
        value = " ".join(value.split())
        if key and value:
            found.append((key, value))
    return found


def format_banner(color: bool) -> str:
    return _banner(_ART, _MARK, _TAG, color)


def format_field(key: str, value: str, color: bool) -> str:
    if not color:
        return f"{key}\t{value}"
    return f"  {_CYAN}{key:<12}{_RESET} {_WHITE}{value}{_RESET}"


def _fetch(host: str, port: int, name: str, timeout: float) -> tuple[str, bool]:
    query = name.encode("idna") + b"\r\n"
    chunks = bytearray()
    with socket.create_connection((host, port), timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(query)
        while len(chunks) < _MAX_BYTES:
            piece = sock.recv(min(4096, _MAX_BYTES - len(chunks)))
            if not piece:
                break
            chunks.extend(piece)
    return bytes(chunks).decode("utf-8", "replace"), len(chunks) >= _MAX_BYTES


def _first(found: dict[str, list[str]], keys: tuple[str, ...]) -> str:
    for key in keys:
        values = found.get(key)
        if values:
            return values[0]
    return ""


def _when_text(parsed: object, raw: object) -> str:
    if isinstance(parsed, datetime):
        return parsed.strftime("%Y-%m-%d %H:%M:%SZ")
    if isinstance(raw, str):
        return raw[:300]
    return ""


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


class RegistryError(Exception):
    pass
