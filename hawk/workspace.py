"""Engagement scope shared by the built-in modules.

The directory is `$WEBHAWK_SCOPE` or `./.webhawk`. `scope.txt` lists hosts,
domains, `*.domains`, and CIDRs. A domain includes its subdomains. Loopback
is always in scope so a local lab does not need an entry.
"""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from urllib.parse import urlsplit

_HEADER = """# WebHawk scope. One host, domain, *.domain, or CIDR per line.
# A domain includes its subdomains. *.example.com is subdomains only.
# Loopback is always allowed.
#   app.internal
#   *.lab.internal
#   10.1.0.0/16
"""


def workspace_dir() -> Path:
    override = os.environ.get("WEBHAWK_SCOPE", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.cwd() / ".webhawk"


def scope_path() -> Path:
    return workspace_dir() / "scope.txt"


def urls_path() -> Path:
    return workspace_dir() / "urls.txt"


def requests_dir() -> Path:
    return workspace_dir() / "requests"


def scope_is_active() -> bool:
    return scope_path().is_file()


def init_workspace() -> Path:
    """Create the scope directory. An existing scope file is left as it is."""
    root = workspace_dir()
    root.mkdir(parents=True, exist_ok=True)
    requests_dir().mkdir(parents=True, exist_ok=True)
    if not urls_path().exists():
        urls_path().write_text("", encoding="utf-8")
    if not scope_path().exists():
        scope_path().write_text(_HEADER, encoding="utf-8")
    return root


def read_entries() -> list[str]:
    if not scope_path().is_file():
        return []
    entries: list[str] = []
    for line in scope_path().read_text(encoding="utf-8", errors="replace").splitlines():
        text = line.strip()
        if text and not text.startswith("#"):
            entries.append(text)
    return entries


def normalize_entry(token: str) -> str:
    """Return the scope line to store, or raise ValueError."""
    text = token.strip()
    if not text or any(ch.isspace() for ch in text):
        raise ValueError(f"{token!r} is not a host, domain, or CIDR.")
    if "://" in text:
        host = urlsplit(text).hostname
        if not host:
            raise ValueError(f"{token!r} has no host.")
        return host.lower().rstrip(".")
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"{token!r} is not a CIDR.") from exc
        return str(network)
    return text.lower().rstrip(".")


def add_entries(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Add scope lines. Returns (added, already present). Raises ValueError."""
    init_workspace()
    current = read_entries()
    known = {item.lower() for item in current}
    added: list[str] = []
    already: list[str] = []
    for token in tokens:
        entry = normalize_entry(token)
        if entry.lower() in known:
            already.append(entry)
            continue
        current.append(entry)
        known.add(entry.lower())
        added.append(entry)
    _write_entries(current)
    return added, already


def remove_entries(tokens: list[str]) -> tuple[list[str], list[str]]:
    """Remove scope lines. Returns (removed, not present)."""
    if not scope_is_active():
        return [], [token.strip() for token in tokens if token.strip()]
    wanted = {normalize_entry(token).lower() for token in tokens}
    current = read_entries()
    removed = [entry for entry in current if entry.lower() in wanted]
    kept = [entry for entry in current if entry.lower() not in wanted]
    found = {entry.lower() for entry in removed}
    missing = [token.strip() for token in tokens if normalize_entry(token).lower() not in found]
    _write_entries(kept)
    return removed, missing


def read_urls() -> list[str]:
    if not urls_path().is_file():
        return []
    return [
        line.strip()
        for line in urls_path().read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def remember_urls(urls: list[str]) -> int:
    """Append new URLs to the workspace list. Returns how many were new."""
    if not scope_is_active():
        return 0
    init_workspace()
    existing = read_urls()
    known = set(existing)
    fresh = [url for url in urls if url not in known]
    if not fresh:
        return 0
    with urls_path().open("a", encoding="utf-8") as handle:
        for url in fresh:
            known.add(url)
            handle.write(url + "\n")
    return len(fresh)


def save_request(name: str, data: bytes) -> Path:
    if not scope_is_active():
        raise ValueError("No scope workspace yet. Run: webhawk scope init")
    safe = Path(name).name
    if not safe or safe in {".", ".."}:
        raise ValueError("Pick a file name for the saved request.")
    init_workspace()
    path = requests_dir() / safe
    path.write_bytes(data)
    return path


def allowed(target: str) -> bool:
    """True for loopback, and for hosts listed in an active scope file."""
    host = hostname_of(target)
    if not host:
        return False
    if is_loopback(host):
        return True
    if not scope_is_active():
        return False
    return matches(host, read_entries())


def hostname_of(target: str) -> str:
    text = target.strip()
    if "://" in text:
        return (urlsplit(text).hostname or "").lower().rstrip(".")
    host, _port = split_host(text)
    return host.lower().rstrip(".")


def split_host(value: str) -> tuple[str, str | None]:
    text = value.strip()
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return text, None
        host = text[1:end]
        rest = text[end + 1 :]
        port = rest[1:] if rest.startswith(":") and rest[1:] else None
        return host, port
    if text.count(":") == 1:
        host, port = text.split(":")
        return host, port or None
    return text, None


def is_loopback(host: str) -> bool:
    name = host.lower().rstrip(".")
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


def matches(host: str, entries: list[str]) -> bool:
    """True when `host` is covered by a scope entry. IPs do not suffix-match."""
    name = host.lower().rstrip(".")
    host_is_ip = _is_ip(name)
    for raw in entries:
        entry = raw.strip().lower().rstrip(".")
        if not entry or entry.startswith("#"):
            continue
        network = _network(entry)
        if network is not None:
            if host_is_ip and ipaddress.ip_address(name) in network:
                return True
            continue
        if _is_ip(entry) or host_is_ip:
            if name == entry:
                return True
            continue
        if entry.startswith("*."):
            parent = entry[2:]
            if parent and name.endswith("." + parent):
                return True
            continue
        if name == entry or name.endswith("." + entry):
            return True
    return False


def explain_block(host: str) -> str:
    if not scope_is_active():
        return (
            f"{host} was not contacted. There is no scope file yet.\n"
            "  webhawk scope init\n"
            f"  webhawk scope add {host}"
        )
    return f"{host} is outside this scope.\n  webhawk scope add {host}"


def _write_entries(entries: list[str]) -> None:
    body = _HEADER + "".join(entry + "\n" for entry in entries)
    scope_path().write_text(body, encoding="utf-8")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if "/" not in value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
