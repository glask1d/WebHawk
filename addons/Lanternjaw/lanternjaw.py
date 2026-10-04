#!/usr/bin/env python3
"""
Lanternjaw — deep-sea phishing threat intel for the public phishunt.io API.

phishunt publishes active suspicious-phishing detections (CC0, no auth) with
IP, ASN, certificate, and multi-source verdicts. This client queries that
API. It does not connect to the suspicious sites themselves.

The optional `deep` command calls phishunt's own active analyzer, which
fetches the URL on their side. Everything else is passive.

    python3 lanternjaw.py pulse
    python3 lanternjaw.py hunt --company paypal --tier verified
    python3 lanternjaw.py analyze https://example.com
    python3 lanternjaw.py match proxies.txt --fresh
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

NAME = "Lanternjaw"
VERSION = "1.0.0"
BASE = "https://phishunt.io"
DOCS = "https://phishunt.io/api/"
USER_AGENT = f"{NAME}/{VERSION} (+{DOCS}; defensive threat-intel CLI)"
CACHE_NAME = "feed.json"
CACHE_TTL = 600  # phishunt caches the static feed for 15 minutes
RATE = 8.0  # documented ceiling is 10 req/s per IP
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

FEEDS = {
    "json": "/feed.json",
    "csv": "/feed.csv",
    "txt": "/feed.txt",
    "stix": "/stix/bundle.json",
}
BLOCKLISTS = {
    "domains": "/blocklist/domains.txt",
    "hosts": "/blocklist/hosts.txt",
    "adblock": "/blocklist/adblock.txt",
    "dnsmasq": "/blocklist/dnsmasq.conf",
    "unbound": "/blocklist/unbound.conf",
    "rpz": "/blocklist/rpz.zone",
}
SOURCES = (
    ("malicious_google", "G", "Google Safe Browsing"),
    ("malicious_openphish", "O", "OpenPhish"),
    ("malicious_phishtank", "P", "PhishTank"),
    ("malicious_tweetfeed", "T", "TweetFeed"),
    ("malicious_urlscan", "U", "urlscan.io"),
)
VERDICT_STYLE = {
    "critical": "bold bright_red",
    "high": "bold orange1",
    "medium": "bold yellow",
    "low": "green",
    "noise": "dim",
    "phishing": "bold bright_red",
    "likely_phishing": "bold bright_red",
    "suspicious": "bold yellow",
    "minimal": "dim",
}
PAAS_SUFFIXES = (
    "pages.dev",
    "vercel.app",
    "github.io",
    "blogspot.com",
    "web.app",
    "firebaseapp.com",
    "workers.dev",
    "netlify.app",
    "azurewebsites.net",
    "herokuapp.com",
    "glitch.me",
    "r2.dev",
    "webflow.io",
    "myshopify.com",
    "square.site",
    "teachable.com",
    "godaddysites.com",
)
PATH_TOKENS = ("login", "signin", "sign-in", "verify", "verification", "secure", "wallet", "account", "password", "update")
PIVOT_FIELDS = ("ip", "asn", "org", "cert", "country", "company", "registrar")

theme = Theme(
    {
        "info": "cyan",
        "warn": "bold yellow",
        "err": "bold bright_red",
        "ok": "bold bright_green",
        "muted": "grey58",
        "head": "bold bright_white",
        "accent": "bold bright_cyan",
        "lure": "bold bright_yellow",
        "jaw": "bold bright_magenta",
    }
)
console = Console(stderr=True, theme=theme, highlight=False)

# Human-readable mode vs machine-readable stdout.
STATE: dict[str, bool] = {"json": False, "live": False}


class PhishuntError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, payload: Any = None):
        super().__init__(message)
        self.status = status
        self.payload = payload


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
                 .--------------------------------------.
                 |   L A N T E R N J A W    v{ver:<7}|
                 |   the lure hunts back                |
                 '--------------------------------------'
                              \   *
                               \ /|
                          ______\ |___________
                     ____/                 \____
                  __/    \    (o)   (o)    /    \__
                 /        \      <JAW>    /        \
                |  phish  '.___hunt___.'   intel    |
                 \______________|__________________/
                                |
        phishunt.io   ·   CC0   ·   passive unless you ask for deep
""".format(ver=VERSION)


def print_banner() -> None:
    text = Text()
    for line in BANNER.strip("\n").splitlines():
        if "*" in line or "/|" in line:
            style = "lure"
        elif "LANTERN" in line or "lure hunts" in line or line.strip().startswith(("|", "'", ".")):
            style = "jaw"
        elif "phishunt.io" in line:
            style = "ok"
        else:
            style = "accent"
        text.append(line + "\n", style=style)
    console.print(text)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class Client:
    """Polite phishunt client. Stays under 10 req/s and backs off on 429."""

    def __init__(self, timeout: float = 45.0, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.min_interval = 1.0 / RATE
        self._next = 0.0
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/json, text/csv, text/plain;q=0.8, */*;q=0.5",
            }
        )

    def _wait(self) -> None:
        now = time.monotonic()
        delay = self._next - now
        if delay > 0:
            time.sleep(delay)
            now = time.monotonic()
        self._next = now + self.min_interval

    def request(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> requests.Response:
        url = path if path.startswith("http") else BASE + path
        clean = {k: v for k, v in (params or {}).items() if v is not None and v != ""}
        last_exc: Exception | None = None
        for attempt in range(4):
            self._wait()
            try:
                resp = self.session.get(
                    url,
                    params=clean or None,
                    headers=headers,
                    timeout=timeout or self.timeout,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                last_exc = exc
                if attempt == 3:
                    raise PhishuntError(f"network error talking to phishunt: {exc}") from exc
                time.sleep(1.2 * (attempt + 1))
                continue

            host = urllib.parse.urlparse(resp.url).netloc.lower()
            if host not in {"phishunt.io", "www.phishunt.io"}:
                raise PhishuntError(f"refusing to follow a redirect off phishunt.io ({host})")

            if self.verbose:
                console.print(f"[muted]GET {resp.status_code} {resp.url}[/muted]")

            if resp.status_code == 429:
                retry = _retry_after(resp)
                payload = _maybe_json(resp)
                # Budget exhaustion can ask us to wait until UTC midnight. Don't sit on that.
                if retry is None:
                    retry = float(min(30, 2 ** attempt))
                if retry > 90 or attempt == 3:
                    raise PhishuntError(_http_message(resp, payload), resp.status_code, payload)
                note(f"[warn]429 rate limited[/warn] — sleeping {retry:.0f}s")
                time.sleep(retry)
                continue

            if resp.status_code >= 500 and attempt < 3:
                time.sleep(1.2 * (attempt + 1))
                continue

            if resp.status_code >= 400:
                payload = _maybe_json(resp)
                raise PhishuntError(_http_message(resp, payload), resp.status_code, payload)
            return resp

        raise PhishuntError(f"network error talking to phishunt: {last_exc}")

    def get_json(self, path: str, params: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        resp = self.request(path, params, **kwargs)
        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise PhishuntError(f"invalid JSON from {resp.url}: {exc}") from exc

    def get_text(self, path: str, params: dict[str, Any] | None = None, **kwargs: Any) -> tuple[str, requests.Response]:
        resp = self.request(path, params, **kwargs)
        resp.encoding = resp.encoding or "utf-8"
        return resp.text, resp


def _retry_after(resp: requests.Response) -> float | None:
    raw = resp.headers.get("Retry-After")
    if not raw:
        payload = _maybe_json(resp)
        if isinstance(payload, dict) and payload.get("retry_after") is not None:
            raw = str(payload["retry_after"])
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


def _maybe_json(resp: requests.Response) -> Any:
    text = resp.text or ""
    if not text or text[:1] not in "{[":
        return None
    try:
        return resp.json()
    except json.JSONDecodeError:
        return None


def _http_message(resp: requests.Response, payload: Any) -> str:
    detail = ""
    extra = ""
    if isinstance(payload, dict):
        detail = str(payload.get("error") or payload.get("message") or "")
        bits = []
        if payload.get("budget"):
            bits.append(f"budget={payload['budget']}")
        if payload.get("retry_after") is not None:
            bits.append(f"retry_after={payload['retry_after']}s")
        extra = (" (" + ", ".join(bits) + ")") if bits else ""
    if not detail:
        detail = (resp.text or "").strip().replace("\n", " ")[:180]
    if resp.status_code == 403:
        detail = detail or "403 from the edge. API routes accept this User-Agent; retry shortly."
    return f"HTTP {resp.status_code} — {detail}{extra}".rstrip()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def note(msg: str) -> None:
    if not STATE["json"]:
        console.print(msg)


def emit_json(data: Any) -> None:
    sys.stdout.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def short_time(value: Any) -> str:
    if not value:
        return "—"
    return str(value).replace("T", " ")[:16]


def tiny_time(value: Any) -> str:
    text = short_time(value)
    if len(text) >= 16 and text[4] == "-":
        return text[5:16]
    return text


def flag(value: Any) -> bool:
    """Source flags arrive as booleans on the feed and as '0'/'1' on campaign members."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def source_count(site: dict[str, Any]) -> int:
    return sum(1 for key, _glyph, _label in SOURCES if flag(site.get(key)))


def site_score(site: dict[str, Any]) -> int:
    for key in ("score", "phishunt_score", "url_risk_score"):
        raw = site.get(key)
        if raw is None or raw == "":
            continue
        try:
            return int(float(raw))
        except (TypeError, ValueError):
            continue
    return 0


def verdict_of(site: dict[str, Any]) -> str:
    return str(site.get("verdict") or site.get("url_risk") or "—")


def defang(value: str) -> str:
    v = value or ""
    v = (
        v.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace("https:", "hxxps:")
        .replace("http:", "hxxp:")
    )
    sentinel = "\0"
    v = v.replace("[.]", sentinel)
    v = v.replace(".", "[.]")
    v = v.replace(sentinel, "[.]")
    return v


def refang(value: str) -> str:
    v = (value or "").strip().strip("\"'")
    v = (
        v.replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .replace("hxxps:", "https:")
        .replace("hxxp:", "http:")
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("{.}", ".")
    )
    return v


def plain(value: Any, kind: str = "text") -> Text:
    """Untrusted API text for a Rich cell. Brackets stay literal (defang uses [.] )."""
    return Text(show(value, kind=kind))


def show(value: Any, *, kind: str = "text") -> str:
    text = "" if value is None else str(value)
    if not text:
        return "—"
    if STATE["live"]:
        return text
    if kind in {"url", "domain", "ip", "host"}:
        return defang(text)
    return text


def host_of(value: str) -> str:
    v = refang(value).strip().rstrip(".")
    if not v:
        return ""
    candidate = v
    if "://" not in candidate and ("/" in candidate or "?" in candidate):
        candidate = "http://" + candidate
    if "://" in candidate:
        try:
            parsed = urllib.parse.urlparse(candidate)
        except ValueError:
            return ""
        return (parsed.hostname or "").lower().rstrip(".")
    return v.lower().split("/")[0].split("?")[0].rstrip(".")


def looks_like_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "lanternjaw" / CACHE_NAME


def read_cache(path: Path, max_age: float | None) -> list[dict[str, Any]] | None:
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return None
    if max_age is not None and age > max_age:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    sites = payload.get("sites") if isinstance(payload, dict) else payload
    if not isinstance(sites, list):
        return None
    return sites


def write_cache(path: Path, sites: list[dict[str, Any]]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps({"saved_at": now_iso(), "count": len(sites), "sites": sites}, ensure_ascii=False),
            encoding="utf-8",
        )
        tmp.replace(path)
    except OSError as exc:
        note(f"[warn]could not write feed cache:[/warn] {exc}")


def load_feed(client: Client, *, fresh: bool) -> list[dict[str, Any]]:
    path = cache_path()
    if not fresh:
        cached = read_cache(path, CACHE_TTL)
        if cached is not None:
            age = int(time.time() - path.stat().st_mtime)
            note(f"[muted]active feed cache[/muted]  {len(cached)} rows  ·  {age}s old  ·  [muted]--fresh to reload[/muted]")
            return cached
    with console.status("[accent]pulling phishunt active feed…[/accent]", spinner="dots"):
        data = client.get_json("/feed.json", timeout=90)
    if not isinstance(data, list):
        raise PhishuntError("feed.json was not a JSON array")
    write_cache(path, data)
    note(f"[ok]feed[/ok]  {len(data)} active rows")
    return data


def server_params(args: argparse.Namespace) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for key in ("company", "since", "contains", "tier", "asn", "org", "registrar", "cert", "country", "ip"):
        value = getattr(args, key, None)
        if value:
            params[key] = value
    if params.get("asn"):
        params["asn"] = str(params["asn"]).removeprefix("AS").removeprefix("as")
    if params.get("company"):
        params["company"] = str(params["company"]).strip().lower()
    if params.get("contains"):
        raw = re.sub(r"[^A-Za-z0-9._-]", "", str(params["contains"]))
        if len(raw) < 3 or len(raw) > 80:
            raise PhishuntError("--contains must be 3–80 characters of letters, digits, or -._", status=400)
        params["contains"] = raw
    return params


def stamp_key(value: Any) -> str:
    """Comparable prefix of an ISO timestamp. Z and +00:00 collapse to the same 19 chars."""
    text = str(value or "").strip().replace("Z", "+00:00")
    return text[:19]


def narrow_sites(sites: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    """Apply hunt filters locally. Used when both sides of a diff must mean the same slice."""
    params = server_params(args)
    if getattr(args, "tier", None):
        note("[warn]--tier is not applied on a saved snapshot. The feed does not say which rows had a screenshot.[/warn]")
    contains = str(params.get("contains") or "").lower()
    since = stamp_key(params.get("since"))
    wanted_asn = str(params.get("asn") or "")
    out: list[dict[str, Any]] = []
    for site in sites:
        if params.get("company") and str(site.get("company") or "").lower() != params["company"]:
            continue
        for field in ("country", "org", "cert", "ip", "registrar"):
            if params.get(field) and str(site.get(field) or "") != str(params[field]):
                break
        else:
            if wanted_asn:
                got = str(site.get("asn") or "")
                if got.removeprefix("AS").removeprefix("as") != wanted_asn:
                    continue
            if contains:
                blob = f"{site.get('url') or ''} {site.get('domain') or ''}".lower()
                if contains not in blob:
                    continue
            if since:
                seen = stamp_key(site.get("first_seen"))
                if seen and seen < since:
                    continue
            out.append(site)
            continue
        continue
    return client_filter(out, args)


def client_filter(sites: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    verdict = (getattr(args, "verdict", None) or "").lower()
    min_score = getattr(args, "min_score", None)
    min_sources = getattr(args, "min_sources", None)
    out = []
    for site in sites:
        if verdict and verdict_of(site).lower() != verdict:
            continue
        if min_score is not None and site_score(site) < min_score:
            continue
        if min_sources is not None and source_count(site) < min_sources:
            continue
        out.append(site)
    return out


def sort_sites(sites: list[dict[str, Any]], how: str) -> list[dict[str, Any]]:
    if how == "score":
        return sorted(sites, key=lambda s: (site_score(s), source_count(s), str(s.get("first_seen") or "")), reverse=True)
    if how == "sources":
        return sorted(sites, key=lambda s: (source_count(s), site_score(s), str(s.get("first_seen") or "")), reverse=True)
    if how == "brand":
        return sorted(sites, key=lambda s: (str(s.get("company") or ""), str(s.get("first_seen") or "")), reverse=True)
    return sorted(sites, key=lambda s: str(s.get("first_seen") or ""), reverse=True)


def gather(client: Client, args: argparse.Namespace) -> tuple[list[dict[str, Any]], str]:
    """Return the working set and a short label of where it came from."""
    params = server_params(args)
    if params:
        if getattr(args, "offset", None):
            params["limit"] = getattr(args, "limit", None) or 100
            params["offset"] = args.offset
            data = client.get_json("/api/v1/domains", params)
            rows = list(data.get("results") or [])
            label = f"api page offset={args.offset} total={data.get('total')}"
        else:
            rows = page_domains(client, params)
            label = f"api/v1/domains  {len(rows)} matches"
    else:
        rows = load_feed(client, fresh=bool(getattr(args, "fresh", False)))
        label = f"active feed  {len(rows)} rows"
    rows = client_filter(rows, args)
    rows = sort_sites(rows, getattr(args, "sort", None) or "first_seen")
    return rows, label


def page_domains(client: Client, params: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    offset = 0
    total = None
    while offset <= 10000:
        query = dict(params)
        query["limit"] = 1000
        query["offset"] = offset
        data = client.get_json("/api/v1/domains", query)
        batch = list(data.get("results") or [])
        total = data.get("total", total)
        fresh = 0
        for site in batch:
            uid = str(site.get("uuid") or "")
            if uid:
                if uid in seen:
                    continue
                seen.add(uid)
            rows.append(site)
            fresh += 1
        if fresh == 0 or not batch:
            break
        offset += len(batch)
        if total is not None and offset >= int(total):
            break
        if len(batch) < 1000:
            break
    if total is not None and len(rows) < int(total):
        note(
            f"[warn]fetched {len(rows)} of {total}[/warn] — "
            "the domains API caps offset at 10000. Use `feed json` for the unfiltered full set."
        )
    return rows


def clip(rows: list[dict[str, Any]], args: argparse.Namespace, default: int | None = 25) -> list[dict[str, Any]]:
    if getattr(args, "all", False):
        return rows
    limit = getattr(args, "limit", None)
    if limit is None:
        limit = default
    if not limit or limit >= len(rows):
        return rows
    return rows[:limit]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def style_verdict(value: Any) -> Text:
    label = str(value or "—")
    return Text(label, style=VERDICT_STYLE.get(label.lower(), "white"))


def source_text(site: dict[str, Any]) -> Text:
    text = Text()
    for key, glyph, _label in SOURCES:
        text.append(glyph, style="bold bright_white" if flag(site.get(key)) else "grey35")
    return text


def score_text(score: int) -> Text:
    if score >= 80:
        style = "bold bright_red"
    elif score >= 60:
        style = "bold orange1"
    elif score >= 40:
        style = "bold yellow"
    elif score > 0:
        style = "green"
    else:
        style = "dim"
    bar_w = 8
    filled = round(bar_w * max(0, min(score, 100)) / 100)
    text = Text(f"{score:>3} ", style=style)
    text.append("█" * filled, style=style)
    text.append("░" * (bar_w - filled), style="grey35")
    return text


def detail_link(site: dict[str, Any]) -> str | None:
    company = str(site.get("company") or "")
    uid = str(site.get("uuid") or "")
    if SLUG_RE.match(company) and UUID_RE.match(uid):
        return f"{BASE}/suspicious/{company}/{uid}/"
    return None


def sites_table(rows: list[dict[str, Any]]) -> Table:
    # 80-column terminals have to keep the domain. Extra columns appear when there is room.
    wide = console.size.width >= 110
    table = Table(
        box=box.SIMPLE_HEAVY,
        header_style="head",
        expand=True,
        pad_edge=False,
        caption="src G/O/P/T/U = google, openphish, phishtank, tweetfeed, urlscan · bright = flagged, dim ≠ clean",
        caption_style="muted",
    )
    table.add_column("seen", style="muted", no_wrap=True, width=11)
    table.add_column("sc", no_wrap=True, width=3)
    table.add_column("brand", style="bright_cyan", overflow="ellipsis", max_width=14)
    table.add_column("domain", overflow="fold", ratio=3, min_width=16)
    if wide:
        table.add_column("ip", overflow="ellipsis", max_width=24)
        table.add_column("geo", overflow="ellipsis", max_width=16)
    table.add_column("src", no_wrap=True, width=5)
    for site in rows:
        verdict = verdict_of(site)
        score = Text(f"{site_score(site):>3}", style=VERDICT_STYLE.get(verdict.lower(), "white"))
        cells: list[Any] = [
            tiny_time(site.get("first_seen")),
            score,
            plain(site.get("company") or "—"),
            plain(site.get("domain"), "domain"),
        ]
        if wide:
            cells.append(plain(site.get("ip"), "ip"))
            cells.append(plain(site.get("country") or "—"))
        cells.append(source_text(site))
        table.add_row(*cells)
    return table


def kv_table(pairs: list[tuple[str, Any]], *, title: str | None = None) -> Table:
    table = Table(box=box.SIMPLE, show_header=False, expand=True, pad_edge=False, title=title)
    table.add_column("k", style="muted", no_wrap=True)
    table.add_column("v", overflow="fold")
    for key, value in pairs:
        if value is None or value == "" or value == [] or value == {}:
            continue
        if isinstance(value, (dict, list)):
            rendered = json.dumps(value, ensure_ascii=False)
        else:
            rendered = str(value)
        table.add_row(key, Text(rendered))
    return table


def print_sites(rows: list[dict[str, Any]], label: str, total: int) -> None:
    console.print(Panel(f"[head]{escape(label)}[/head]", border_style="cyan", subtitle=f"{len(rows)} shown of {total}"))
    if not rows:
        console.print("[warn]nothing matched.[/warn]")
        return
    console.print(sites_table(rows))
    if len(rows) < total:
        console.print(f"[muted]{total - len(rows)} more not shown — raise --limit or pass --all[/muted]")


def export_sites(rows: list[dict[str, Any]], path: str) -> None:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    lower = dest.name.lower()
    if lower.endswith(".json"):
        dest.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    elif lower.endswith(".txt"):
        dest.write_text("".join(str(r.get("url") or r.get("domain") or "") + "\n" for r in rows), encoding="utf-8")
    else:
        if not lower.endswith(".csv"):
            dest = dest.with_suffix(dest.suffix + ".csv")
        fields = [
            "uuid", "first_seen", "date", "verdict", "score", "company", "domain", "url",
            "ip", "country", "asn", "org", "cert",
            "malicious_google", "malicious_openphish", "malicious_phishtank",
            "malicious_tweetfeed", "malicious_urlscan",
        ]
        with dest.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({key: row.get(key, "") for key in fields})
    note(f"[ok]wrote[/ok] {dest}  ({len(rows)} rows, live indicators)")


def write_text(path: str, text: str) -> None:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
    note(f"[ok]wrote[/ok] {dest}  ({len(text):,} bytes)")


def counter_table(title: str, counts: Counter[str], limit: int, *, value_name: str = "n") -> None:
    table = Table(title=title, box=box.SIMPLE_HEAVY, header_style="head", expand=True)
    table.add_column(value_name, overflow="fold")
    table.add_column("count", justify="right", style="bright_white")
    table.add_column("", ratio=2)
    top = counts.most_common(limit)
    peak = top[0][1] if top else 1
    for name, count in top:
        width = max(1, round(18 * count / peak))
        bar = Text("█" * width, style="cyan")
        table.add_row(Text(name or "—"), str(count), bar)
    console.print(table)


def summarize(sites: list[dict[str, Any]]) -> dict[str, Any]:
    verdicts: Counter[str] = Counter()
    brands: Counter[str] = Counter()
    countries: Counter[str] = Counter()
    asns: Counter[str] = Counter()
    orgs: Counter[str] = Counter()
    certs: Counter[str] = Counter()
    tlds: Counter[str] = Counter()
    scores = []
    source_hits = Counter()
    consensus = Counter()
    noise_flagged = 0
    puny = 0
    paas = 0
    pathy = 0
    for site in sites:
        verdicts[verdict_of(site)] += 1
        brands[str(site.get("company") or "—")] += 1
        countries[str(site.get("country") or "—")] += 1
        asn = str(site.get("asn") or "—")
        org = str(site.get("org") or "—")
        asns[f"AS{asn}  {org}" if asn != "—" else "—"] += 1
        orgs[org] += 1
        certs[str(site.get("cert") or "—")] += 1
        domain = str(site.get("domain") or "").lower()
        tlds[domain.rsplit(".", 1)[-1] if "." in domain else "—"] += 1
        scores.append(site_score(site))
        nsrc = source_count(site)
        consensus[str(nsrc)] += 1
        for key, _glyph, label in SOURCES:
            if flag(site.get(key)):
                source_hits[label] += 1
        if verdict_of(site).lower() in {"noise", "—"} and nsrc > 0:
            noise_flagged += 1
        if "xn--" in domain:
            puny += 1
        if any(domain == suffix or domain.endswith("." + suffix) for suffix in PAAS_SUFFIXES):
            paas += 1
        url = str(site.get("url") or "").lower()
        if any(token in url for token in PATH_TOKENS):
            pathy += 1
    newest = sort_sites(sites, "first_seen")[:8]
    hottest = sort_sites(sites, "score")[:8]
    return {
        "count": len(sites),
        "verdicts": verdicts,
        "brands": brands,
        "countries": countries,
        "asns": asns,
        "orgs": orgs,
        "certs": certs,
        "tlds": tlds,
        "scores": scores,
        "source_hits": source_hits,
        "consensus": consensus,
        "noise_flagged": noise_flagged,
        "puny": puny,
        "paas": paas,
        "pathy": pathy,
        "newest": newest,
        "hottest": hottest,
        "first": min((str(s.get("first_seen") or "") for s in sites), default=""),
        "last": max((str(s.get("first_seen") or "") for s in sites), default=""),
        "checked": max((str(s.get("date") or "") for s in sites), default=""),
    }


def median(nums: list[int]) -> float | None:
    if not nums:
        return None
    ordered = sorted(nums)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2


def render_pulse(stats: dict[str, Any], label: str) -> None:
    count = stats["count"]
    med = median(stats["scores"])
    med_s = f"{med:.0f}" if med is not None else "—"
    headline = Table(box=box.HEAVY, expand=True, header_style="head", title="LANTERNJAW  ·  pulse")
    headline.add_column("active", justify="right")
    headline.add_column("median score", justify="right")
    headline.add_column("brands", justify="right")
    headline.add_column("countries", justify="right")
    headline.add_column("ASNs", justify="right")
    headline.add_row(
        str(count),
        med_s,
        str(len(stats["brands"])),
        str(len(stats["countries"])),
        str(len(stats["asns"])),
    )
    console.print(headline)
    console.print(
        f"[muted]{escape(label)}[/muted]\n"
        f"[muted]first seen {short_time(stats['first'])} → {short_time(stats['last'])}  ·  "
        f"last check {short_time(stats['checked'])}[/muted]"
    )
    console.print(
        "[muted]Scores are phishunt's heuristic, not a probability. "
        "A source flag of false means 'not flagged when checked', not 'clean'. "
        "False positives happen.[/muted]\n"
    )
    counter_table("verdicts", stats["verdicts"], 8, value_name="tier")
    counter_table("targeted brands", stats["brands"], 12, value_name="brand")
    counter_table("hosting countries", stats["countries"], 8, value_name="country")
    counter_table("networks", stats["asns"], 8, value_name="asn / org")
    counter_table("certificate issuers", stats["certs"], 6, value_name="issuer")
    counter_table("external feeds that flagged", stats["source_hits"], 5, value_name="source")

    bits = []
    for n, count_n in sorted(stats["consensus"].items(), key=lambda kv: int(kv[0])):
        bits.append(f"{n} src × {count_n}")
    console.print(Panel(
        "\n".join([
            "  ".join(bits) or "—",
            f"noise-tier but still feed-flagged: {stats['noise_flagged']}",
            f"punycode / xn-- hosts: {stats['puny']}",
            f"shared-platform suffixes (pages.dev, vercel.app, blogspot…): {stats['paas']}",
            f"credential-ish path tokens (login, verify, wallet…): {stats['pathy']}",
        ]),
        title="shape of the slice",
        border_style="magenta",
    ))
    console.print("[head]hottest[/head]")
    console.print(sites_table(stats["hottest"]))
    console.print("[head]newest[/head]")
    console.print(sites_table(stats["newest"]))


def render_signals(signals: Any, *, title: str) -> None:
    if not isinstance(signals, list) or not signals:
        return
    table = Table(title=title, box=box.SIMPLE_HEAVY, header_style="head", expand=True)
    table.add_column("signal", style="bright_cyan", overflow="fold")
    table.add_column("kind", style="muted")
    table.add_column("points", justify="right")
    table.add_column("detail", overflow="fold")
    for item in signals[:8]:
        if not isinstance(item, dict):
            continue
        points = item.get("points", item.get("score_contribution"))
        detail_bits = []
        if item.get("label"):
            detail_bits.append(str(item["label"]))
        if item.get("value") is not None:
            detail_bits.append(f"value {item['value']}")
        if item.get("weight") not in (None, 0, 0.0):
            detail_bits.append(f"w {item['weight']}")
        table.add_row(
            str(item.get("signal") or item.get("signal_id") or "—"),
            str(item.get("kind") or item.get("category") or ""),
            "" if points is None else str(points),
            " · ".join(detail_bits),
        )
    console.print(table)


def render_analyze(data: dict[str, Any], *, heading: str = "PASSIVE ANALYZE", subtitle: str = "target was not contacted") -> None:
    live = data.get("live_analysis") or {}
    query = data.get("query") or {}
    known = data.get("known") or {}
    history = data.get("history") or {}
    feeds = data.get("external_feeds") or {}
    action = data.get("action") or {}
    meta = data.get("meta") or {}
    score = int(live.get("url_risk_score") or 0)
    verdict = str(data.get("verdict") or live.get("url_risk") or "—")
    title = Text.assemble(
        (f" {heading} ", "bold bright_white on grey23"),
        "  ",
        (verdict, VERDICT_STYLE.get(verdict.lower(), "white")),
        "  ",
    )
    console.print(Panel(score_text(score), title=title, subtitle=subtitle, border_style="cyan"))
    console.print(kv_table([
        ("url", show(query.get("url"), kind="url")),
        ("host", show(query.get("host"), kind="host")),
        ("apex", show(query.get("apex"), kind="domain")),
        ("brand match", live.get("brand_match")),
        ("keyword score", live.get("kw_score")),
        ("url risk", f"{live.get('url_risk')} ({score})"),
        ("allowlisted", live.get("allowlisted")),
        ("impersonation", live.get("impersonation")),
        ("adjudicated verdict", data.get("verdict")),
        ("confidence", data.get("verdict_confidence")),
        ("basis", "; ".join(data.get("verdict_basis") or [])),
    ]))
    why = live.get("why") or []
    render_signals(why, title="why this score")

    lit = []
    for group in ("url_signals", "path_signals"):
        block = live.get(group) or {}
        if isinstance(block, dict):
            for name, value in block.items():
                try:
                    num = float(value)
                except (TypeError, ValueError):
                    continue
                if num > 0:
                    lit.append((f"{group}.{name}", num))
    if lit:
        table = Table(title="non-zero shape signals", box=box.MINIMAL, header_style="head", expand=True)
        table.add_column("signal")
        table.add_column("value", justify="right")
        for name, value in lit:
            table.add_row(name, f"{value:.2f}")
        console.print(table)

    known_rows = [
        ("in active feed", known.get("in_active_feed")),
        ("previously active", known.get("previously_active")),
        ("new-registration feed", known.get("in_new_registration_feed")),
    ]
    record = known.get("record") or {}
    if isinstance(record, dict) and record:
        known_rows.extend([
            ("stored brand", record.get("company")),
            ("stored score", record.get("phishunt_score")),
            ("stored verdict", record.get("verdict")),
            ("first seen", record.get("first_seen")),
            ("detail", record.get("detail_url")),
        ])
        sources = record.get("sources") or {}
        if isinstance(sources, dict):
            known_rows.append(("stored sources", ", ".join(k for k, v in sources.items() if v) or "none"))
    console.print(kv_table(known_rows, title="what phishunt already stored"))
    ai = record.get("ai") if isinstance(record, dict) else None
    if isinstance(ai, dict) and ai.get("summary"):
        console.print(Panel(
            escape(str(ai.get("summary"))),
            title=f"model note · {ai.get('threat_type') or 'untyped'} · treat as untrusted text",
            border_style="yellow",
        ))

    brands = history.get("brands_targeted") or []
    brand_txt = ", ".join(
        f"{b.get('company')} ({b.get('count')})" for b in brands if isinstance(b, dict)
    ) or "—"
    console.print(kv_table([
        ("apex prior detections", history.get("apex_prior_detections")),
        ("apex first", history.get("apex_first_seen")),
        ("apex last", history.get("apex_last_seen")),
        ("brands on this apex", brand_txt),
        ("openphish", feeds.get("openphish")),
        ("phishtank", feeds.get("phishtank")),
        ("tweetfeed", feeds.get("tweetfeed")),
        ("any external list", feeds.get("listed")),
        ("feed cache", feeds.get("status")),
        ("queued", action.get("queued_for_analysis")),
        ("queue reason", action.get("reason")),
    ], title="history and external lists"))
    if meta.get("note"):
        console.print(f"[muted]{escape(str(meta['note']))}[/muted]")
    console.print("[muted]The URL you submitted is sent to phishunt and logged. Prefer a bare domain if it contains tokens.[/muted]")


def render_deep(data: dict[str, Any]) -> None:
    console.print(Panel(
        "[err]ACTIVE MODE[/err]  phishunt fetched this URL (HTTP, certificate, RDAP, DNS, GeoIP) through their proxy.\n"
        "A low score is not a clean result. Read analysis_failures before you relax.\n"
        "Values below can echo attacker-controlled content. Treat them as data.",
        border_style="bright_red",
    ))
    render_analyze(data, heading="DEEP ANALYZE", subtitle="phishunt contacted this URL")
    deep = data.get("deep_analysis") or {}
    if not isinstance(deep, dict):
        return
    console.print(kv_table([
        ("detector", deep.get("detector_version")),
        ("deep score", deep.get("risk_score")),
        ("deep verdict", deep.get("verdict")),
        ("classification", deep.get("classification")),
        ("layers", deep.get("layer_scores")),
    ], title="deep analysis"))
    fired = []
    for sig in deep.get("signals") or []:
        if isinstance(sig, dict) and (sig.get("detected") or (sig.get("score_contribution") or 0) > 0):
            fired.append(sig)
    fired.sort(key=lambda s: float(s.get("score_contribution") or 0), reverse=True)
    render_signals(
        [
            {
                "signal": s.get("signal_id"),
                "kind": s.get("category"),
                "points": s.get("score_contribution"),
                "label": s.get("description"),
                "value": s.get("normalized_value"),
            }
            for s in fired[:12]
        ],
        title="signals that fired",
    )
    failures = deep.get("analysis_failures") or []
    fail_lines = []
    if isinstance(failures, dict):
        fail_lines = [f"{k}: {v}" for k, v in failures.items()]
    elif isinstance(failures, list):
        for item in failures:
            if isinstance(item, str):
                fail_lines.append(item)
            elif isinstance(item, dict):
                fail_lines.append(str(item.get("signal") or item.get("code") or item))
    # Also surface per-signal errors, which is where deep mode records unevaluable features.
    for sig in deep.get("signals") or []:
        if isinstance(sig, dict) and sig.get("errors"):
            fail_lines.append(f"{sig.get('signal_id')}: {', '.join(map(str, sig['errors']))}")
    if fail_lines:
        console.print(Panel("\n".join(escape(line) for line in fail_lines[:25]), title="not fully evaluated", border_style="yellow"))
    adjustments = deep.get("adjustments") or []
    if adjustments:
        console.print(kv_table([("adjustments", adjustments[:8])], title="score adjustments"))
    budget = data.get("budget") or {}
    if budget:
        console.print(
            f"[muted]deep budget[/muted]  used {budget.get('used')}  ·  "
            f"remaining {budget.get('remaining')}  ·  limit {budget.get('limit')}"
        )


def render_campaign(data: dict[str, Any]) -> None:
    state = str(data.get("state") or "live")
    confidence = str(data.get("confidence") or data.get("label") or "—")
    border = "bright_red" if "possible" in confidence else "yellow"
    brands = data.get("brands") or []
    console.print(Panel(
        f"[head]{escape(str(data.get('key') or ''))}[/head]  {escape(confidence)}  ·  {escape(state)}\n"
        "Shared infrastructure among public detections. Not an attribution, not an actor name.",
        border_style=border,
        subtitle=str(data.get("data_status") or ""),
    ))
    top = data.get("top_evidence") or {}
    top_txt = ""
    if isinstance(top, dict) and top:
        top_txt = f"{top.get('type')} ({top.get('coverage')})"
    console.print(kv_table([
        ("key", data.get("key")),
        ("legacy id", data.get("id")),
        ("state", state),
        ("end state", data.get("end_state")),
        ("successors", ", ".join(data.get("successors") or [])),
        ("confidence", confidence),
        ("confidence score", data.get("confidence_score")),
        ("size", data.get("size")),
        ("hosts", data.get("host_count")),
        ("active members", data.get("active_count")),
        ("brands", ", ".join(brands) if isinstance(brands, list) else brands),
        ("first seen", data.get("first_seen") or data.get("first_tracked")),
        ("last activity", data.get("last_activity") or data.get("last_seen")),
        ("top evidence", top_txt),
        ("algorithm", data.get("algorithm_version")),
        ("generated", data.get("generated_at")),
        ("data status", data.get("data_status")),
        ("phishunt page", data.get("url")),
    ]))
    evidence = data.get("evidence_summary") or []
    if isinstance(evidence, list) and evidence:
        table = Table(title="evidence", box=box.SIMPLE_HEAVY, header_style="head", expand=True)
        table.add_column("type", style="bright_cyan")
        table.add_column("value", overflow="fold")
        table.add_column("members", justify="right")
        for item in evidence[:20]:
            if not isinstance(item, dict):
                continue
            table.add_row(
                plain(item.get("type") or "—"),
                Text(show(item.get("value"), kind="domain")[:140]),
                str(item.get("members_matching") or ""),
            )
        console.print(table)
    members = data.get("members") or []
    if isinstance(members, list) and members:
        table = Table(title=f"members ({len(members)})", box=box.SIMPLE_HEAVY, header_style="head", expand=True)
        table.add_column("status", no_wrap=True)
        table.add_column("score", justify="right")
        table.add_column("brand", style="bright_cyan")
        table.add_column("domain", overflow="fold")
        table.add_column("ip")
        table.add_column("src", no_wrap=True)
        for member in members[:40]:
            if not isinstance(member, dict):
                continue
            table.add_row(
                plain(member.get("status") or "—"),
                str(site_score(member)),
                plain(member.get("company") or "—"),
                plain(member.get("domain"), "domain"),
                plain(member.get("ip"), "ip"),
                source_text(member),
            )
        console.print(table)
        if len(members) > 40:
            console.print("[muted]member table truncated at 40 — use --json or campaign export for the full set[/muted]")
    rels = data.get("relationships") or []
    if isinstance(rels, list) and rels:
        table = Table(title="strongest pairs", box=box.SIMPLE, header_style="head", expand=True)
        table.add_column("a", overflow="fold")
        table.add_column("b", overflow="fold")
        table.add_column("score", justify="right")
        table.add_column("tier")
        for rel in rels[:12]:
            if not isinstance(rel, dict):
                continue
            table.add_row(
                plain(rel.get("domain_a"), "domain"),
                plain(rel.get("domain_b"), "domain"),
                str(rel.get("score") or ""),
                str(rel.get("tier") or ""),
            )
        console.print(table)
        if data.get("relationships_truncated"):
            console.print("[muted]phishunt capped the pair list at the strongest relationships[/muted]")
    history = data.get("history") or []
    if isinstance(history, list) and history:
        console.print("[head]history[/head]")
        for event in history[:8]:
            if not isinstance(event, dict):
                continue
            joined = event.get("joined") or []
            left = event.get("left") or []
            if not isinstance(joined, list):
                joined = [joined]
            if not isinstance(left, list):
                left = [left]
            plus = ", ".join(show(item, kind="domain") for item in joined) or "—"
            minus = ", ".join(show(item, kind="domain") for item in left) or "—"
            console.print(
                f"  [muted]{short_time(event.get('at'))}[/muted]  {escape(str(event.get('event') or ''))}  "
                f"size {event.get('size')}  +{escape(plus)}  -{escape(minus)}"
            )


def render_related(data: dict[str, Any]) -> None:
    cluster = data.get("cluster") or {}
    console.print(Panel(
        f"[head]{escape(show(data.get('domain'), kind='domain'))}[/head]\n"
        f"algorithm {escape(str(data.get('algorithm_version') or '—'))}  ·  "
        f"built {escape(str(data.get('generated_at') or '—'))}",
        title="related infrastructure",
        subtitle="overlap between public detections, not attribution",
        border_style="magenta",
    ))
    if isinstance(cluster, dict) and cluster:
        console.print(kv_table([
            ("campaign key", cluster.get("key")),
            ("cluster size", cluster.get("size")),
            ("hosts", cluster.get("host_count")),
            ("page", cluster.get("url")),
        ], title="cluster"))
    else:
        console.print("[muted]not currently in a surfaced cluster[/muted]")
    results = data.get("results") or []
    if not results:
        console.print("[warn]no related indicators at this threshold.[/warn]")
        return
    table = Table(box=box.SIMPLE_HEAVY, header_style="head", expand=True)
    table.add_column("score", justify="right")
    table.add_column("status")
    table.add_column("brand", style="bright_cyan")
    table.add_column("domain", overflow="fold")
    table.add_column("evidence", overflow="fold")
    for row in results:
        evidence = row.get("evidence") or []
        ev = ", ".join(
            str(item.get("type")) for item in evidence if isinstance(item, dict)
        )
        table.add_row(
            str(row.get("relationship_score") or ""),
            plain(row.get("status") or ""),
            plain(row.get("company") or "—"),
            plain(row.get("domain"), "domain"),
            Text(ev),
        )
    console.print(table)


def render_enrich(data: dict[str, Any]) -> None:
    whois = data.get("whois") if isinstance(data.get("whois"), dict) else {}
    ipinfo = data.get("ipinfo") if isinstance(data.get("ipinfo"), dict) else {}
    console.print(Panel("RDAP and ipinfo, cached about a day by phishunt. Registrar fields are not identity.", title="enrich", border_style="cyan"))
    if whois:
        console.print(kv_table([
            ("registrar", whois.get("registrar")),
            ("created", whois.get("created")),
            ("updated", whois.get("updated")),
            ("expires", whois.get("expires")),
            ("status", ", ".join(whois.get("status") or [])),
            ("lookup", whois.get("error")),
        ], title="whois / rdap"))
    if ipinfo:
        console.print(kv_table([
            ("city", ipinfo.get("city")),
            ("region", ipinfo.get("region")),
            ("country", ipinfo.get("country")),
            ("postal", ipinfo.get("postal")),
            ("loc", ipinfo.get("loc")),
            ("hostname", show(ipinfo.get("hostname"), kind="host") if ipinfo.get("hostname") else None),
            ("lookup", ipinfo.get("error")),
        ], title="ip geo"))


def find_uuid(sites: list[dict[str, Any]], uid: str) -> dict[str, Any] | None:
    for site in sites:
        if str(site.get("uuid") or "").lower() == uid.lower():
            return site
    return None


def render_site_card(site: dict[str, Any]) -> None:
    console.print(Panel(show(site.get("url"), kind="url"), title=show(site.get("domain"), kind="domain"), border_style="bright_cyan"))
    console.print(kv_table([
        ("uuid", site.get("uuid")),
        ("brand", site.get("company")),
        ("verdict", verdict_of(site)),
        ("score", site_score(site)),
        ("first seen", site.get("first_seen")),
        ("last check", site.get("date")),
        ("ip", show(site.get("ip"), kind="ip")),
        ("country", site.get("country")),
        ("asn", site.get("asn")),
        ("org", site.get("org")),
        ("cert", site.get("cert")),
        ("registrar", site.get("registrar")),
        ("sources", "".join(glyph if flag(site.get(key)) else glyph.lower() for key, glyph, _label in SOURCES)),
        ("phishunt", detail_link(site)),
        ("sans score", site.get("sans_score")),
        ("sans reason", site.get("sans_scorereason")),
    ]))
    render_signals(site.get("top_signals"), title="top signals")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_about(_args: argparse.Namespace) -> int:
    console.print(Panel(
        "\n".join([
            "Public phishing intelligence from phishunt.io. No API key on the open endpoints.",
            "Pipeline: hourly detections, 6-hour rechecks, daily new-registration scan.",
            "Sources: Certificate Transparency, Google Safe Browsing, OpenPhish, PhishTank, TweetFeed, urlscan.io.",
            "Enrichment: IP, ASN, org, country, TLS issuer (ipinfo.io).",
            "Rate limit: 10 requests/second/IP. This client stays near 8 and honors Retry-After.",
            "Population: active detections, minus high-confidence parked domains and hostname-intent clones. PaaS kits stay in.",
            "Campaigns are shared-infrastructure clusters. Labels are 'possible campaign' or 'suspected cluster' only.",
            "Deep analysis is the one authenticated, active call. It is off unless you run `deep --yes`.",
        ]),
        title="what you are looking at",
        border_style="cyan",
    ))
    table = Table(title="endpoints this client calls", box=box.SIMPLE_HEAVY, header_style="head", expand=True)
    table.add_column("command")
    table.add_column("method and path", overflow="fold")
    rows = [
        ("pulse / hunt / triage / pivot / match / snapshot", "GET /feed.json or GET /api/v1/domains"),
        ("search", "GET /api/v1/search.json"),
        ("analyze", "GET /api/v1/analyze"),
        ("deep", "GET /api/v1/analyze/deep"),
        ("campaigns / campaign", "GET /api/v1/campaigns/{key} and /export"),
        ("related", "GET /api/v1/domains/{uuid}/related"),
        ("enrich", "GET /api/v1/enrich/{uuid}/"),
        ("brand", "GET /api/v1/brands/{slug}.json"),
        ("cert", "GET /api/v1/certs/{cert}.json"),
        ("feed", "GET /feed.json, /feed.csv, /feed.txt, /stix/bundle.json"),
        ("blocklist", "GET /blocklist/ domains, hosts, adblock, dnsmasq, unbound, rpz"),
    ]
    for command, path in rows:
        table.add_row(Text(command), Text(path))
    console.print(table)
    console.print(f"[muted]docs {DOCS}[/muted]")
    return 0


def cmd_pulse(args: argparse.Namespace) -> int:
    sites, label = gather(client_of(args), args_as_full(args))
    if args.json:
        stats = summarize(sites)
        emit_json({
            "count": stats["count"],
            "verdicts": stats["verdicts"],
            "brands": stats["brands"].most_common(30),
            "countries": stats["countries"].most_common(20),
            "asns": stats["asns"].most_common(20),
            "certs": stats["certs"].most_common(15),
            "sources": stats["source_hits"],
            "noise_flagged": stats["noise_flagged"],
            "punycode": stats["puny"],
            "paas_suffix": stats["paas"],
            "credential_path": stats["pathy"],
            "median_score": median(stats["scores"]),
        })
        return 0
    if not sites:
        console.print("[warn]empty slice.[/warn]")
        return 0
    render_pulse(summarize(sites), label)
    return 0


def args_as_full(args: argparse.Namespace) -> argparse.Namespace:
    """Stats commands always want the whole match set, not a display page."""
    clone = argparse.Namespace(**vars(args))
    clone.all = True
    clone.offset = None
    if not getattr(clone, "sort", None):
        clone.sort = "first_seen"
    return clone


def client_of(args: argparse.Namespace) -> Client:
    return Client(timeout=args.timeout, verbose=args.verbose)


def cmd_hunt(args: argparse.Namespace) -> int:
    client = client_of(args)
    if args.offset:
        rows, label = gather(client, args)
    else:
        full = args_as_full(args)
        rows, label = gather(client, full)
    total = len(rows)
    shown = rows if args.all or args.offset else rows[: (args.limit or 25)]
    if args.json:
        emit_json(shown)
        return 0
    if args.values:
        for site in shown:
            sys.stdout.write(show(site.get("url") or site.get("domain"), kind="url") + "\n")
    else:
        print_sites(shown, label, total)
    if args.export:
        export_sites(shown, args.export)
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    if len(args.query.strip()) < 3:
        raise PhishuntError("search needs at least 3 characters", status=400)
    data = client_of(args).get_json("/api/v1/search.json", {"q": args.query, "limit": args.limit or 50})
    rows = list(data.get("results") or [])
    rows = sort_sites(client_filter(rows, args), args.sort or "first_seen")
    if args.json:
        emit_json(data if not (args.verdict or args.min_score or args.min_sources) else rows)
        return 0
    print_sites(rows, f"search {args.query!r}  ·  api count {data.get('count')}", len(rows))
    if args.export:
        export_sites(rows, args.export)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    url = normalize_url(args.url)
    data = client_of(args).get_json("/api/v1/analyze", {"url": url})
    if args.json:
        emit_json(data)
        return 0
    render_analyze(data)
    return 0


def cmd_deep(args: argparse.Namespace) -> int:
    token = args.token or os.environ.get("PHISHUNT_DEEP_TOKEN") or ""
    if not token:
        raise PhishuntError("deep analysis needs PHISHUNT_DEEP_TOKEN or --token. It is not a free endpoint.")
    if not args.yes:
        raise PhishuntError(
            "refusing to run an active fetch without --yes. "
            "phishunt will contact the URL, log it, and spend the shared daily budget (50)."
        )
    url = normalize_url(args.url)
    note("[warn]asking phishunt to fetch the URL. This can take 5–15 seconds.[/warn]")
    data = client_of(args).get_json(
        "/api/v1/analyze/deep",
        {"url": url},
        headers={"X-Phishunt-Deep-Token": token},
        timeout=max(args.timeout, 90),
    )
    if args.json:
        emit_json(data)
        return 0
    render_deep(data)
    return 0


def normalize_url(raw: str) -> str:
    url = refang(raw).strip()
    if not url:
        raise PhishuntError("url is empty", status=400)
    if "://" not in url:
        url = "https://" + url
        note(f"[muted]assuming https://[/muted]  {show(url, kind='url')}")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or "." not in parsed.hostname:
        raise PhishuntError("url must be http(s) with a dotted hostname", status=400)
    if len(url) > 2048:
        raise PhishuntError("url is longer than 2048 characters", status=400)
    return url


def cmd_campaigns(args: argparse.Namespace) -> int:
    client = client_of(args)
    if args.all and not args.offset:
        rows = []
        offset = 0
        total = None
        meta: dict[str, Any] = {}
        while offset <= 10000:
            data = client.get_json("/api/v1/campaigns", {
                "limit": 200,
                "offset": offset,
                "brand": (args.brand or "").lower() or None,
                "status": args.status,
                "min_size": args.min_size,
            })
            meta = data
            batch = list(data.get("results") or [])
            rows.extend(batch)
            total = data.get("total", total)
            if not batch or (total is not None and offset + len(batch) >= int(total)):
                break
            offset += len(batch)
        data = dict(meta)
        data["results"] = rows
        data["count"] = len(rows)
    else:
        data = client.get_json("/api/v1/campaigns", {
            "limit": args.limit or 20,
            "offset": args.offset or 0,
            "brand": (args.brand or "").lower() or None,
            "status": args.status,
            "min_size": args.min_size,
        })
    if args.json:
        emit_json(data)
        return 0
    status = data.get("data_status")
    border = "cyan" if status in (None, "ok") else "yellow"
    console.print(Panel(
        f"algorithm {escape(str(data.get('algorithm_version') or '—'))}  ·  "
        f"built {escape(str(data.get('generated_at') or '—'))}  ·  "
        f"data {escape(str(status or '—'))}\n"
        f"{data.get('count')} on this page  ·  {data.get('total')} matched",
        title="possible campaigns / suspected clusters",
        border_style=border,
    ))
    if status and status != "ok":
        console.print("[warn]correlation sidecar is stale or missing. An empty list may mean the nightly job did not run.[/warn]")
    table = Table(box=box.SIMPLE_HEAVY, header_style="head", expand=True)
    table.add_column("key", style="bright_magenta", no_wrap=True)
    table.add_column("confidence")
    table.add_column("size", justify="right")
    table.add_column("live", justify="right")
    table.add_column("brands", overflow="fold")
    table.add_column("evidence", overflow="fold")
    table.add_column("last", style="muted", no_wrap=True)
    for row in data.get("results") or []:
        evidence = row.get("top_evidence") or {}
        ev = f"{evidence.get('type')} {evidence.get('coverage')}" if isinstance(evidence, dict) else ""
        table.add_row(
            str(row.get("key") or ""),
            style_verdict_label(str(row.get("confidence") or "")),
            str(row.get("size") or ""),
            str(row.get("active_count") or ""),
            Text(", ".join(row.get("brands") or [])),
            Text(ev),
            short_time(row.get("last_activity")),
        )
    console.print(table)
    console.print("[muted]open one with `campaign KEY`. The numeric id changes daily; the key does not.[/muted]")
    return 0


def style_verdict_label(label: str) -> Text:
    style = "bold bright_red" if "possible" in label else "bold yellow" if "suspected" in label else "white"
    return Text(label or "—", style=style)


def cmd_campaign(args: argparse.Namespace) -> int:
    client = client_of(args)
    key = args.key.strip()
    if args.export:
        text, resp = client.get_text(f"/api/v1/campaigns/{urllib.parse.quote(key)}/export", {"format": args.export})
        if args.json or args.export == "json":
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise PhishuntError(f"export was not JSON: {exc}") from exc
            if args.out:
                write_text(args.out, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
            if args.json:
                emit_json(data)
                return 0
            render_campaign(data)
            return 0
        if args.out:
            write_text(args.out, text if text.endswith("\n") else text + "\n")
        else:
            sys.stdout.write(text if text.endswith("\n") else text + "\n")
        _ = resp
        return 0
    data = client.get_json(f"/api/v1/campaigns/{urllib.parse.quote(key)}")
    if args.json:
        emit_json(data)
        return 0
    render_campaign(data)
    return 0


def cmd_related(args: argparse.Namespace) -> int:
    require_uuid(args.uuid)
    data = client_of(args).get_json(
        f"/api/v1/domains/{args.uuid}/related",
        {"limit": args.limit or 10, "min_score": args.min_score or 0},
    )
    if args.json:
        emit_json(data)
        return 0
    render_related(data)
    return 0


def cmd_enrich(args: argparse.Namespace) -> int:
    require_uuid(args.uuid)
    data = client_of(args).get_json(f"/api/v1/enrich/{args.uuid}/")
    if args.json:
        emit_json(data)
        return 0
    render_enrich(data)
    return 0


def require_uuid(value: str) -> None:
    if not UUID_RE.match(value or ""):
        raise PhishuntError("that does not look like a uuid from the feed", status=400)


def cmd_brand(args: argparse.Namespace) -> int:
    slug = args.slug.strip().lower()
    data = client_of(args).get_json(f"/api/v1/brands/{urllib.parse.quote(slug)}.json")
    if args.json:
        emit_json(data)
        return 0
    console.print(Panel(escape(str(data.get("name") or slug)), subtitle=str(data.get("vertical") or data.get("category") or ""), border_style="bright_cyan"))
    console.print(kv_table([
        ("slug", data.get("slug")),
        ("sector", data.get("sector")),
        ("vertical", data.get("vertical") or data.get("category")),
        ("domain", data.get("domain")),
        ("active phishings", data.get("active_phishings")),
        ("notes", data.get("notes")),
        ("page", data.get("url")),
    ]))
    return 0


def cmd_cert(args: argparse.Namespace) -> int:
    name = args.name.strip()
    data = client_of(args).get_json(f"/api/v1/certs/{urllib.parse.quote(name)}.json")
    if args.json:
        emit_json(data)
        return 0
    console.print(Panel(escape(str(data.get("cert") or name)), title="certificate issuer", border_style="yellow"))
    console.print(kv_table([
        ("operator", data.get("operator")),
        ("root", data.get("root_ca")),
        ("since", data.get("since")),
        ("key", data.get("key_type")),
        ("use", data.get("use_case")),
        ("related", ", ".join(data.get("related") or [])),
        ("active phishings", data.get("active_phishings")),
        ("notes", data.get("notes")),
        ("page", data.get("url")),
    ]))
    console.print("[muted]A free CA on a phishing site is common. Presence alone is not a signal — phishunt says so too.[/muted]")
    return 0


def cmd_feed(args: argparse.Namespace) -> int:
    client = client_of(args)
    path = FEEDS[args.kind]
    if args.kind in {"json", "stix"}:
        data = client.get_json(path, timeout=90)
        if args.out:
            write_text(args.out, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        if args.json:
            emit_json(data)
            return 0
        if args.kind == "json" and isinstance(data, list):
            render_pulse(summarize(data), "feed.json")
            return 0
        objects = data.get("objects") if isinstance(data, dict) else []
        indicators = [o for o in objects or [] if isinstance(o, dict) and o.get("type") == "indicator"]
        conf = [int(o["confidence"]) for o in indicators if isinstance(o.get("confidence"), (int, float))]
        labels: Counter[str] = Counter()
        for obj in indicators:
            for label in obj.get("labels") or []:
                labels[str(label)] += 1
        console.print(Panel(
            f"{len(indicators)} indicators  ·  {len(objects or [])} bundle objects  ·  "
            f"confidence present on {len(conf)}",
            title="STIX 2.1 bundle",
            border_style="bright_magenta",
        ))
        if conf:
            console.print(f"[muted]confidence min {min(conf)}  median {median(conf):.0f}  max {max(conf)}[/muted]")
        counter_table("indicator labels (brands)", labels, 12, value_name="label")
        console.print("[muted]Each indicator's confidence is that detection's own score, not one flat number. TLP:CLEAR.[/muted]")
        return 0

    text, _resp = client.get_text(path, timeout=90)
    if args.out:
        write_text(args.out, text if text.endswith("\n") else text + "\n")
    if args.json:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
        return 0
    lines = text.splitlines()
    console.print(f"[ok]{args.kind}[/ok]  {len(lines):,} lines  ·  {len(text):,} bytes")
    preview = lines[: (args.limit or 15)]
    for line in preview:
        rendered = defang(line) if not STATE["live"] else line
        console.print(Text(rendered, style="cyan"))
    if len(lines) > len(preview):
        console.print(f"[muted]… {len(lines) - len(preview)} more lines. --out writes the raw feed.[/muted]")
    return 0


def cmd_blocklist(args: argparse.Namespace) -> int:
    text, _resp = client_of(args).get_text(BLOCKLISTS[args.kind], timeout=90)
    if args.out:
        write_text(args.out, text if text.endswith("\n") else text + "\n")
        return 0
    if args.values or args.json:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
        return 0
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#") and not ln.startswith("!")]
    console.print(Panel(
        f"{args.kind}  ·  {len(lines):,} usable lines  ·  {len(text):,} bytes\n"
        "These lists collapse each detection to a registrable domain so a resolver can block it. "
        "Shared hosts (Blogspot, GitBook, and similar) stay at the phishing hostname, not the bare provider.",
        border_style="bright_green",
    ))
    for line in lines[: (args.limit or 20)]:
        console.print(Text(defang(line) if not STATE["live"] else line))
    console.print("[muted]pass --out FILE for the raw list a blocker should consume. Refresh it on a timer; the upstream set is hourly.[/muted]")
    return 0


def cmd_pivot(args: argparse.Namespace) -> int:
    if args.field not in PIVOT_FIELDS:
        raise PhishuntError(f"pivot field must be one of: {', '.join(PIVOT_FIELDS)}", status=400)
    sites, label = gather(client_of(args), args_as_full(args))
    buckets: dict[str, dict[str, Any]] = {}
    missing = 0
    for site in sites:
        raw = site.get(args.field)
        key = str(raw).strip() if raw not in (None, "", "-") else ""
        if not key:
            missing += 1
            continue
        if args.field == "asn" and key.isdigit():
            key = "AS" + key
        bucket = buckets.setdefault(key, {"n": 0, "brands": Counter(), "countries": Counter(), "scores": [], "sample": site.get("domain") or ""})
        bucket["n"] += 1
        bucket["brands"][str(site.get("company") or "—")] += 1
        bucket["countries"][str(site.get("country") or "—")] += 1
        bucket["scores"].append(site_score(site))
    ordered = sorted(buckets.items(), key=lambda kv: kv[1]["n"], reverse=True)
    ordered = [(k, b) for k, b in ordered if b["n"] >= (args.min_count or 2)]
    if args.json:
        emit_json([
            {
                "value": key,
                "count": bucket["n"],
                "brands": bucket["brands"].most_common(5),
                "countries": bucket["countries"].most_common(3),
                "median_score": median(bucket["scores"]),
                "sample": bucket["sample"],
            }
            for key, bucket in ordered[: args.limit or 30]
        ])
        return 0
    console.print(Panel(
        f"grouped by [head]{args.field}[/head]  ·  {escape(label)}\n"
        f"{len(ordered)} buckets with at least {args.min_count or 2} members  ·  {missing} rows had no {args.field}",
        border_style="magenta",
    ))
    if args.field == "registrar" and missing == len(sites):
        console.print("[warn]the active feed does not currently ship registrar. `hunt --registrar VALUE` still filters server-side.[/warn]")
    table = Table(box=box.SIMPLE_HEAVY, header_style="head", expand=True)
    table.add_column(args.field, overflow="fold")
    table.add_column("n", justify="right")
    table.add_column("med", justify="right")
    table.add_column("brands", overflow="fold")
    table.add_column("sample", overflow="fold")
    for key, bucket in ordered[: args.limit or 25]:
        brands = ", ".join(f"{name} {n}" for name, n in bucket["brands"].most_common(3))
        med = median(bucket["scores"])
        shown_key = show(key, kind="ip" if args.field == "ip" else "text")
        table.add_row(
            Text(shown_key),
            str(bucket["n"]),
            f"{med:.0f}" if med is not None else "—",
            Text(brands),
            plain(bucket["sample"], "domain"),
        )
    console.print(table)
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    args.sort = "score"
    sites, label = gather(client_of(args), args_as_full(args))
    shown = sites if args.all else sites[: (args.limit or 20)]
    if args.json:
        emit_json(shown)
        return 0
    console.print(Panel(
        f"sorted by score, then how many external feeds flagged the row\n{escape(label)}",
        title="triage",
        border_style="orange1",
    ))
    print_sites(shown, "hottest first", len(sites))
    if shown:
        console.print("[head]lead row[/head]")
        render_site_card(shown[0])
    if args.export:
        export_sites(shown, args.export)
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    require_uuid(args.uuid)
    client = client_of(args)
    site = find_uuid(load_feed(client, fresh=bool(args.fresh)), args.uuid)
    related = None
    enrich = None
    if not args.skip_related:
        try:
            related = client.get_json(f"/api/v1/domains/{args.uuid}/related", {"limit": args.limit or 10, "min_score": 0})
        except PhishuntError as exc:
            related = {"error": str(exc)}
    if not args.skip_enrich:
        try:
            enrich = client.get_json(f"/api/v1/enrich/{args.uuid}/")
        except PhishuntError as exc:
            enrich = {"error": str(exc)}
    if args.json:
        emit_json({"active": site, "related": related, "enrich": enrich})
        return 0
    if site:
        render_site_card(site)
    else:
        console.print("[warn]uuid is not in the current active feed.[/warn] It may be a prior detection or a new registration.")
        if isinstance(related, dict) and related.get("domain"):
            console.print(f"[muted]related endpoint knows it as[/muted] {show(related.get('domain'), kind='domain')}")
    if isinstance(related, dict):
        if related.get("error"):
            console.print(f"[warn]related:[/warn] {escape(str(related['error']))}")
        else:
            render_related(related)
    if isinstance(enrich, dict):
        if enrich.get("error") and "whois" not in enrich:
            console.print(f"[warn]enrich:[/warn] {escape(str(enrich['error']))}")
        else:
            render_enrich(enrich)
    return 0


def load_indicators(path: str) -> list[str]:
    if path == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(path).read_text(encoding="utf-8", errors="replace")
    values = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Allow a CSV-ish first column without pulling in a full dialect guess.
        if "," in line and "://" not in line:
            line = line.split(",")[0].strip().strip("\"'")
        values.append(line)
    return values


def cmd_match(args: argparse.Namespace) -> int:
    try:
        indicators = load_indicators(args.file)
    except OSError as exc:
        raise PhishuntError(f"could not read {args.file}: {exc}") from exc
    sites = load_feed(client_of(args), fresh=bool(args.fresh))
    by_domain: dict[str, list[dict[str, Any]]] = {}
    by_ip: dict[str, list[dict[str, Any]]] = {}
    by_url: dict[str, list[dict[str, Any]]] = {}
    for site in sites:
        domain = str(site.get("domain") or "").lower().rstrip(".")
        ip = str(site.get("ip") or "")
        url = str(site.get("url") or "").lower()
        if domain:
            by_domain.setdefault(domain, []).append(site)
        if ip:
            by_ip.setdefault(ip, []).append(site)
        if url:
            by_url.setdefault(url, []).append(site)

    hits = []
    misses = []
    for raw in indicators:
        found, reason = match_one(raw, by_domain, by_ip, by_url)
        if found:
            hits.append({"indicator": raw, "reason": reason, "sites": found})
        else:
            misses.append(raw)
    if args.json:
        emit_json({
            "indicators": len(indicators),
            "hit_indicators": len(hits),
            "miss_indicators": len(misses),
            "hits": [
                {
                    "indicator": hit["indicator"],
                    "reason": hit["reason"],
                    "uuids": [s.get("uuid") for s in hit["sites"]],
                    "domains": [s.get("domain") for s in hit["sites"]],
                }
                for hit in hits
            ],
            "misses": misses if args.show_misses else [],
        })
        return 1 if args.fail_on_hit and hits else 0

    console.print(Panel(
        f"checked {len(indicators)} indicators against {len(sites)} active detections\n"
        f"[ok]{len(hits)} hit[/ok]   [muted]{len(misses)} miss[/muted]",
        title="match",
        border_style="bright_red" if hits else "green",
    ))
    if hits:
        table = Table(box=box.SIMPLE_HEAVY, header_style="head", expand=True)
        table.add_column("indicator", overflow="fold")
        table.add_column("why", style="yellow")
        table.add_column("brand")
        table.add_column("domain", overflow="fold")
        table.add_column("score", justify="right")
        for hit in hits:
            site = hit["sites"][0]
            extra = f" +{len(hit['sites']) - 1}" if len(hit["sites"]) > 1 else ""
            table.add_row(
                plain(hit["indicator"], "url"),
                hit["reason"],
                plain(site.get("company") or "—"),
                Text(show(site.get("domain"), kind="domain") + extra),
                str(site_score(site)),
            )
        console.print(table)
    if args.show_misses and misses:
        console.print("[head]misses[/head]")
        for item in misses:
            console.print(f"  [muted]{escape(show(item, kind='url'))}[/muted]")
    if args.export and hits:
        flat = []
        for hit in hits:
            for site in hit["sites"]:
                row = dict(site)
                row["matched_indicator"] = hit["indicator"]
                row["match_reason"] = hit["reason"]
                flat.append(row)
        export_sites(flat, args.export)
    return 1 if args.fail_on_hit and hits else 0


def match_one(
    raw: str,
    by_domain: dict[str, list[dict[str, Any]]],
    by_ip: dict[str, list[dict[str, Any]]],
    by_url: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], str]:
    text = refang(raw).strip().lower()
    if not text:
        return [], ""
    host = host_of(text)
    if looks_like_ipv4(text) or looks_like_ipv4(host):
        ip = text if looks_like_ipv4(text) else host
        return by_ip.get(ip, []), "ip"
    url_key = text if "://" in text else ""
    if url_key and url_key in by_url:
        return by_url[url_key], "exact-url"
    if host and host in by_domain:
        return by_domain[host], "exact-domain"
    # Suffix matches require a dotted name so a bare TLD like "com" cannot hit the whole feed.
    if host and "." in host:
        under = []
        parents = []
        for domain, group in by_domain.items():
            if "." in domain and domain.endswith("." + host):
                under.extend(group)
            elif "." in domain and host.endswith("." + domain):
                parents.extend(group)
        if under:
            return _dedupe(under), "subdomain-of-indicator"
        if parents:
            return _dedupe(parents), "under-known-phish-host"
    return [], ""


def _dedupe(sites: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for site in sites:
        uid = str(site.get("uuid") or id(site))
        if uid in seen:
            continue
        seen.add(uid)
        out.append(site)
    return out


def cmd_watch(args: argparse.Namespace) -> int:
    client = client_of(args)
    since = args.since or now_iso()
    seen: set[str] = set()
    interval = max(30, args.interval or 300)
    console.print(Panel(
        f"polling new detections since {since} every {interval}s\n"
        "Ctrl-C stops. The upstream pipeline itself refreshes about hourly.",
        title="watch",
        border_style="bright_yellow",
    ))
    while True:
        params: dict[str, Any] = {"since": since, "limit": 1000}
        if args.company:
            params["company"] = args.company.lower()
        if args.country:
            params["country"] = args.country
        if args.tier:
            params["tier"] = args.tier
        data = client.get_json("/api/v1/domains", params)
        fresh = []
        newest = since
        for site in data.get("results") or []:
            uid = str(site.get("uuid") or "")
            # The API's `since` follows last-check time, so rechecks of old rows come back.
            # Watch is for first-seen arrivals. The cursor still moves on `date`.
            stamp = str(site.get("date") or site.get("first_seen") or "")
            if stamp > newest:
                newest = stamp
            if uid and uid in seen:
                continue
            if uid:
                seen.add(uid)
            first_seen = stamp_key(site.get("first_seen"))
            if first_seen and first_seen < stamp_key(since):
                continue
            fresh.append(site)
        fresh = sort_sites(client_filter(fresh, args), "first_seen")
        if args.json:
            if fresh:
                emit_json({"since": since, "count": len(fresh), "results": fresh})
        elif fresh:
            note(f"\n[lure]{len(fresh)} new[/lure]  [muted]{now_iso()}[/muted]")
            console.print(sites_table(fresh[: args.limit or 50]))
        else:
            note(f"[muted]{now_iso()}[/muted]  quiet  ·  window after {since}")
        if args.log and fresh:
            with open(args.log, "a", encoding="utf-8") as fh:
                for site in fresh:
                    fh.write(json.dumps(site, ensure_ascii=False) + "\n")
        if newest > since:
            since = newest
        if args.once:
            return 0
        time.sleep(interval)


def cmd_snapshot(args: argparse.Namespace) -> int:
    sites = load_feed(client_of(args), fresh=bool(args.fresh))
    path = args.out or f"lanternjaw-snapshot-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    payload = {"tool": NAME, "version": VERSION, "saved_at": now_iso(), "count": len(sites), "sites": sites}
    write_text(path, json.dumps(payload, ensure_ascii=False) + "\n")
    if args.json:
        emit_json({"path": path, "count": len(sites), "saved_at": payload["saved_at"]})
    return 0


def load_snapshot(path: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PhishuntError(f"could not read snapshot {path}: {exc}") from exc
    sites = payload.get("sites") if isinstance(payload, dict) else payload
    if not isinstance(sites, list):
        raise PhishuntError("snapshot did not contain a sites array")
    return sites


def cmd_diff(args: argparse.Namespace) -> int:
    # Both sides go through the same local filters. A --company diff of a full
    # snapshot against an API brand page would otherwise mark every other brand "gone".
    before = narrow_sites(load_snapshot(args.snapshot), args)
    current = narrow_sites(load_feed(client_of(args), fresh=True), args)
    label = "fresh active feed"
    old = {str(s.get("uuid")): s for s in before if s.get("uuid")}
    new = {str(s.get("uuid")): s for s in current if s.get("uuid")}
    added = [new[k] for k in new.keys() - old.keys()]
    gone = [old[k] for k in old.keys() - new.keys()]
    added = sort_sites(added, "first_seen")
    gone = sort_sites(gone, "first_seen")
    if args.json:
        emit_json({
            "before": len(old),
            "now": len(new),
            "added": len(added),
            "gone": len(gone),
            "added_rows": added,
            "gone_rows": gone,
        })
        return 0
    console.print(Panel(
        f"snapshot {len(old)}  →  now {len(new)} ({escape(label)})\n"
        f"[ok]+{len(added)} new uuids[/ok]    [warn]-{len(gone)} no longer in this slice[/warn]",
        title="diff",
        border_style="bright_cyan",
    ))
    if added:
        console.print("[head]added[/head]")
        console.print(sites_table(added[: args.limit or 20]))
    if gone:
        console.print("[head]gone[/head]")
        console.print(sites_table(gone[: args.limit or 20]))
    if args.export:
        export_sites(added, args.export)
    return 0


def md_cell(value: Any, *, kind: str = "text") -> str:
    text = show(value, kind=kind)
    return text.replace("|", "\\|").replace("\n", " ")


def cmd_report(args: argparse.Namespace) -> int:
    sites, label = gather(client_of(args), args_as_full(args))
    stats = summarize(sites)
    hot = stats["hottest"][: args.limit or 15]
    new = stats["newest"][: args.limit or 15]
    lines = [
        f"# Lanternjaw brief",
        "",
        f"Generated {now_iso()} by {NAME} {VERSION}.",
        f"Source slice: {label}.",
        "",
        "phishunt.io data is best-effort and CC0. False positives occur. "
        "A detection-source value of false means the source did not flag the row when checked, not that the row is clean. "
        "Scores are heuristics, not probabilities. Campaign language in other commands is shared infrastructure, not attribution.",
        "",
        "## Snapshot",
        "",
        f"- Rows: {stats['count']}",
        f"- Median score: {median(stats['scores'])}",
        f"- First seen: {stats['first'] or '—'}",
        f"- Newest first-seen: {stats['last'] or '—'}",
        f"- Latest recheck: {stats['checked'] or '—'}",
        f"- Noise-tier but feed-flagged: {stats['noise_flagged']}",
        f"- Punycode hosts: {stats['puny']}",
        f"- Shared-platform suffixes: {stats['paas']}",
        f"- Credential-ish paths: {stats['pathy']}",
        "",
        "## Verdicts",
        "",
    ]
    for name, count in stats["verdicts"].most_common():
        lines.append(f"- {name}: {count}")
    lines += ["", "## Targeted brands", ""]
    for name, count in stats["brands"].most_common(15):
        lines.append(f"- {name}: {count}")
    lines += ["", "## Hosting", ""]
    lines.append("Countries: " + ", ".join(f"{n} ({c})" for n, c in stats["countries"].most_common(8)))
    lines.append("")
    lines.append("Networks: " + ", ".join(f"{n} ({c})" for n, c in stats["asns"].most_common(8)))
    lines.append("")
    lines.append("Issuers: " + ", ".join(f"{n} ({c})" for n, c in stats["certs"].most_common(6)))
    lines += ["", "## Hottest", "", "| score | verdict | brand | domain | ip | sources |", "| --- | --- | --- | --- | --- | --- |"]
    for site in hot:
        glyphs = "".join(glyph if flag(site.get(key)) else "-" for key, glyph, _label in SOURCES)
        lines.append(
            f"| {site_score(site)} | {md_cell(verdict_of(site))} | {md_cell(site.get('company'))} | "
            f"{md_cell(site.get('domain'), kind='domain')} | {md_cell(site.get('ip'), kind='ip')} | {glyphs} |"
        )
    lines += ["", "## Newest", "", "| first seen | brand | domain | score |", "| --- | --- | --- | --- |"]
    for site in new:
        lines.append(
            f"| {md_cell(short_time(site.get('first_seen')))} | {md_cell(site.get('company'))} | "
            f"{md_cell(site.get('domain'), kind='domain')} | {site_score(site)} |"
        )
    lines += [
        "",
        "## Defanged indicators (hottest)",
        "",
        "```",
    ]
    for site in hot:
        lines.append(defang(str(site.get("url") or site.get("domain") or "")))
    lines += ["```", "", f"Upstream docs: {DOCS}", ""]
    body = "\n".join(lines)
    if args.out:
        write_text(args.out, body)
    else:
        sys.stdout.write(body)
    return 0


def cmd_self_test(_args: argparse.Namespace) -> int:
    assert defang("https://evil.example/a") == "hxxps://evil[.]example/a"
    assert defang(defang("http://a.b")) == "hxxp://a[.]b"
    assert refang("hxxps://evil[.]example/a") == "https://evil.example/a"
    assert host_of("hxxps://Login.Example.com/path") == "login.example.com"
    assert looks_like_ipv4("203.0.113.10")
    assert flag("1") and flag(True) and flag(1)
    assert not flag("0") and not flag(False) and not flag(0) and not flag(None)
    sample = {
        "malicious_google": False,
        "malicious_openphish": "1",
        "malicious_phishtank": 0,
        "malicious_tweetfeed": False,
        "malicious_urlscan": True,
        "score": "40",
    }
    assert source_count(sample) == 2
    assert site_score(sample) == 40
    assert median([1, 9, 3]) == 3
    domains = {"paypal-login.example": [{"uuid": "1", "domain": "paypal-login.example"}]}
    ips = {"203.0.113.5": [{"uuid": "2", "domain": "x.test"}]}
    urls: dict[str, list[dict[str, Any]]] = {}
    found, reason = match_one("paypal-login[.]example", domains, ips, urls)
    assert reason == "exact-domain" and found
    found, reason = match_one("203.0.113.5", domains, ips, urls)
    assert reason == "ip"
    found, reason = match_one("nope.invalid", domains, ips, urls)
    assert found == []
    found, reason = match_one("com", {"a.com": [{"uuid": "9", "domain": "a.com"}]}, {}, {})
    assert found == [] and reason == ""
    found, reason = match_one("a.com", {"sub.a.com": [{"uuid": "8", "domain": "sub.a.com"}]}, {}, {})
    assert reason == "subdomain-of-indicator" and len(found) == 1
    assert stamp_key("2026-09-27T00:00:00Z") == stamp_key("2026-09-27T00:00:00+00:00")
    sliced = narrow_sites(
        [
            {"uuid": "1", "company": "paypal", "domain": "a.test", "url": "https://a.test", "first_seen": "2026-09-02T00:00:00Z"},
            {"uuid": "2", "company": "google", "domain": "b.test", "url": "https://b.test", "first_seen": "2026-09-03T00:00:00Z"},
        ],
        argparse.Namespace(
            company="PayPal", since="2026-09-01", contains=None, tier=None, asn=None,
            org=None, registrar=None, cert=None, country=None, ip=None,
            verdict=None, min_score=None, min_sources=None,
        ),
    )
    assert [row["uuid"] for row in sliced] == ["1"]
    print("lanternjaw self-test ok")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class BannerParser(argparse.ArgumentParser):
    def print_help(self) -> None:
        if "-q" not in sys.argv and "--quiet" not in sys.argv:
            print_banner()
        super().print_help()


def add_server_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--company", help="targeted brand slug, e.g. paypal, amazon")
    parser.add_argument("--since", help="ISO date or timestamp, entries after this moment")
    parser.add_argument("--contains", help="substring of the stored URL (3–80 chars, letters/digits/-._)")
    parser.add_argument("--tier", choices=("all", "verified"), help="verified = screenshot or positive urlscan verdict")
    parser.add_argument("--asn", help="AS number, with or without the AS prefix")
    parser.add_argument("--org", help="exact hosting org, as the API spells it")
    parser.add_argument("--registrar", help="exact registrar, as the API spells it")
    parser.add_argument("--cert", help="exact certificate issuer")
    parser.add_argument("--country", help="exact country name, e.g. Germany")
    parser.add_argument("--ip", help="exact IPv4, as the API spells it")


def add_client_filters(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--verdict", choices=("critical", "high", "medium", "low", "noise"), help="client-side verdict tier")
    parser.add_argument("--min-score", type=int, help="client-side minimum phishunt score")
    parser.add_argument("--min-sources", type=int, help="client-side minimum number of external feeds that flagged the row")


def build_parser() -> argparse.ArgumentParser:
    parser = BannerParser(
        prog="lanternjaw.py",
        description="Deep-sea phishing threat intel for the public phishunt.io API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  lanternjaw.py pulse
  lanternjaw.py hunt --company microsoft --tier verified --min-sources 1
  lanternjaw.py triage --since 2026-09-01 --limit 30
  lanternjaw.py pivot asn --min-count 3
  lanternjaw.py analyze https://amazon-secure-login.example.com/signin
  lanternjaw.py inspect <uuid>
  lanternjaw.py campaigns --status active --brand coinbase
  lanternjaw.py match proxy-hosts.txt --fresh --fail-on-hit
  lanternjaw.py snapshot --fresh && lanternjaw.py diff lanternjaw-snapshot-....json
  lanternjaw.py blocklist domains --out phishunt-domains.txt
  lanternjaw.py report --company paypal --out paypal.md

Screen output defangs URLs and IPs. Pass --live when you really want the raw text.
--json prints the machine payload on stdout. Tables stay on stderr.
""".strip(),
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="skip the banner")
    parser.add_argument("-v", "--verbose", action="store_true", help="print each HTTP status on stderr")
    parser.add_argument("--live", action="store_true", help="show live URLs and IPs instead of defanged text")
    parser.add_argument("--fresh", action="store_true", help="ignore the 10-minute active-feed cache")
    parser.add_argument("--timeout", type=float, default=45.0, help="HTTP timeout in seconds (default 45)")
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--json", action="store_true", help="write JSON to stdout")

    about = sub.add_parser("about", help="what this client covers, and the endpoint map")
    about.set_defaults(func=cmd_about)

    pulse = sub.add_parser("pulse", help="situational dashboard for the active set")
    common(pulse)
    add_server_filters(pulse)
    add_client_filters(pulse)
    pulse.set_defaults(func=cmd_pulse, sort="first_seen", all=True, offset=None)

    hunt = sub.add_parser("hunt", help="query active detections")
    common(hunt)
    add_server_filters(hunt)
    add_client_filters(hunt)
    hunt.add_argument("--limit", type=int, default=25, help="rows to show and export (default 25)")
    hunt.add_argument("--offset", type=int, help="raw API page offset; skips the full scan")
    hunt.add_argument("--all", action="store_true", help="do not cap the table or the export")
    hunt.add_argument("--sort", choices=("first_seen", "score", "sources", "brand"), default="first_seen")
    hunt.add_argument("--values", action="store_true", help="print URLs only, to stdout")
    hunt.add_argument("--export", help="write json, csv, or txt (raw indicators)")
    hunt.set_defaults(func=cmd_hunt)

    search = sub.add_parser("search", help="free-text search across URL, domain, and IP")
    common(search)
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=50)
    add_client_filters(search)
    search.add_argument("--sort", choices=("first_seen", "score", "sources", "brand"), default="first_seen")
    search.add_argument("--export")
    search.set_defaults(func=cmd_search)

    analyze = sub.add_parser("analyze", help="passive URL score — phishunt does not contact the target")
    common(analyze)
    analyze.add_argument("url")
    analyze.set_defaults(func=cmd_analyze)

    deep = sub.add_parser("deep", help="ACTIVE phishunt fetch of a URL (token + --yes)")
    common(deep)
    deep.add_argument("url")
    deep.add_argument("--token", help="or set PHISHUNT_DEEP_TOKEN")
    deep.add_argument("--yes", action="store_true", help="confirm the active fetch and budget spend")
    deep.set_defaults(func=cmd_deep)

    camps = sub.add_parser("campaigns", help="list shared-infrastructure clusters")
    common(camps)
    camps.add_argument("--brand")
    camps.add_argument("--status", choices=("active", "all"), default="all")
    camps.add_argument("--min-size", type=int, default=0)
    camps.add_argument("--limit", type=int, default=20)
    camps.add_argument("--offset", type=int, default=0)
    camps.add_argument("--all", action="store_true")
    camps.set_defaults(func=cmd_campaigns)

    camp = sub.add_parser("campaign", help="one cluster by stable key (or legacy numeric id)")
    common(camp)
    camp.add_argument("key")
    camp.add_argument("--export", choices=("json", "csv", "txt"), help="download the attachment form")
    camp.add_argument("--out", help="write --export here; csv/txt without --out go to stdout")
    camp.set_defaults(func=cmd_campaign)

    related = sub.add_parser("related", help="infrastructure overlapping one detection uuid")
    common(related)
    related.add_argument("uuid")
    related.add_argument("--limit", type=int, default=10)
    related.add_argument("--min-score", type=int, default=0)
    related.set_defaults(func=cmd_related)

    enrich = sub.add_parser("enrich", help="RDAP + IP geo for one detection uuid")
    common(enrich)
    enrich.add_argument("uuid")
    enrich.set_defaults(func=cmd_enrich)

    brand = sub.add_parser("brand", help="curated brand metadata and live count")
    common(brand)
    brand.add_argument("slug")
    brand.set_defaults(func=cmd_brand)

    cert = sub.add_parser("cert", help="TLS issuer metadata and live count")
    common(cert)
    cert.add_argument("name")
    cert.set_defaults(func=cmd_cert)

    feed = sub.add_parser("feed", help="download a full feed: json, csv, txt, or stix")
    common(feed)
    feed.add_argument("kind", choices=tuple(FEEDS))
    feed.add_argument("--out")
    feed.add_argument("--limit", type=int, default=15, help="preview lines for text feeds")
    feed.set_defaults(func=cmd_feed)

    block = sub.add_parser("blocklist", help="DNS and filter lists derived from the active set")
    common(block)
    block.add_argument("kind", choices=tuple(BLOCKLISTS))
    block.add_argument("--out", help="raw file for the blocker")
    block.add_argument("--values", action="store_true", help="raw list on stdout")
    block.add_argument("--limit", type=int, default=20, help="preview lines")
    block.set_defaults(func=cmd_blocklist)

    pivot = sub.add_parser("pivot", help="cluster the working set by infrastructure")
    common(pivot)
    pivot.add_argument("field", choices=PIVOT_FIELDS)
    add_server_filters(pivot)
    add_client_filters(pivot)
    pivot.add_argument("--min-count", type=int, default=2)
    pivot.add_argument("--limit", type=int, default=25)
    pivot.set_defaults(func=cmd_pivot, sort="first_seen", all=True, offset=None)

    triage = sub.add_parser("triage", help="hottest rows, score then multi-source agreement")
    common(triage)
    add_server_filters(triage)
    add_client_filters(triage)
    triage.add_argument("--limit", type=int, default=20)
    triage.add_argument("--all", action="store_true")
    triage.add_argument("--export")
    triage.set_defaults(func=cmd_triage, sort="score")

    inspect = sub.add_parser("inspect", help="one uuid: feed card, related infra, WHOIS, geo")
    common(inspect)
    inspect.add_argument("uuid")
    inspect.add_argument("--limit", type=int, default=10, help="related rows")
    inspect.add_argument("--skip-related", action="store_true")
    inspect.add_argument("--skip-enrich", action="store_true")
    inspect.set_defaults(func=cmd_inspect)

    match = sub.add_parser("match", help="check your domains, URLs, or IPs against the active feed")
    common(match)
    match.add_argument("file", help="one indicator per line, or - for stdin. # comments allowed")
    match.add_argument("--show-misses", action="store_true")
    match.add_argument("--fail-on-hit", action="store_true", help="exit 1 when anything matches")
    match.add_argument("--export")
    match.set_defaults(func=cmd_match)

    watch = sub.add_parser("watch", help="poll for detections newer than --since")
    common(watch)
    watch.add_argument("--since", help="ISO timestamp; default is now")
    watch.add_argument("--interval", type=int, default=300, help="seconds between polls (min 30)")
    watch.add_argument("--company")
    watch.add_argument("--country")
    watch.add_argument("--tier", choices=("all", "verified"))
    add_client_filters(watch)
    watch.add_argument("--limit", type=int, default=50)
    watch.add_argument("--once", action="store_true")
    watch.add_argument("--log", help="append new rows as JSON lines")
    watch.set_defaults(func=cmd_watch)

    snap = sub.add_parser("snapshot", help="save the active feed for a later diff")
    common(snap)
    snap.add_argument("--out")
    snap.set_defaults(func=cmd_snapshot)

    diff = sub.add_parser("diff", help="new and gone uuids versus a snapshot")
    common(diff)
    diff.add_argument("snapshot")
    add_server_filters(diff)
    add_client_filters(diff)
    diff.add_argument("--limit", type=int, default=20)
    diff.add_argument("--export", help="write the added rows")
    diff.set_defaults(func=cmd_diff, sort="first_seen", all=True, offset=None, fresh=True)

    report = sub.add_parser("report", help="markdown intel brief")
    common(report)
    add_server_filters(report)
    add_client_filters(report)
    report.add_argument("--limit", type=int, default=15, help="hottest and newest rows in the brief")
    report.add_argument("--out")
    report.set_defaults(func=cmd_report, sort="first_seen", all=True, offset=None)

    test = sub.add_parser("self-test", help="offline checks for defang, flags, and matching")
    test.set_defaults(func=cmd_self_test)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    STATE["json"] = bool(getattr(args, "json", False))
    STATE["live"] = bool(args.live)
    if not args.quiet and not STATE["json"] and args.command != "self-test":
        print_banner()
    try:
        return int(args.func(args))
    except PhishuntError as exc:
        console.print(f"[err]{escape(str(exc))}[/err]")
        if STATE["json"]:
            sys.stderr.write(json.dumps({"error": str(exc), "status": exc.status}) + "\n")
        return 2 if exc.status in {400, 404} else 1
    except KeyboardInterrupt:
        console.print("\n[warn]stopped[/warn]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
