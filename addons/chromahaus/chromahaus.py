#!/usr/bin/env python3
"""
CHROMAHAUS — technicolor threat intel from abuse.ch

A colorful Python 3 CLI for the community APIs:
  URLhaus · MalwareBazaar · ThreatFox · Feodo Tracker · SSLBL

Auth-Key (free): https://auth.abuse.ch/
  export ABUSECH_AUTH_KEY='your-key'
  or: chromahaus.py --key YOUR-KEY ...
  or: ~/.config/chromahaus/auth.key

This tool queries *reported* malware infrastructure and sample metadata.
Live samples are optional, password-zipped, and dangerous. Do not execute
them on a machine you care about.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
NAME = "CHROMAHAUS"
VERSION = "1.1.0"
TAGLINE = "technicolor threat intel from the Swiss house of abuse"
AUTH_PORTAL = "https://auth.abuse.ch/"
DOCS = {
    "urlhaus": "https://urlhaus-api.abuse.ch/",
    "bazaar": "https://bazaar.abuse.ch/api/",
    "threatfox": "https://threatfox.abuse.ch/api/",
}

URLHAUS = "https://urlhaus-api.abuse.ch/v1"
BAZAAR = "https://mb-api.abuse.ch/api/v1/"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_REC = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
FEODO_FULL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
SSLBL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
JA3 = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"

SAMPLE_ZIP_PASSWORD = "infected"
USER_AGENT = f"{NAME}/{VERSION} (+research CLI; python3)"

# ---------------------------------------------------------------------------
# ANSI palette — "the more colors the better"
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITAL = "\033[3m"
    UND = "\033[4m"
    BLINK = "\033[5m"
    INV = "\033[7m"

    BLK = "\033[30m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    BLU = "\033[34m"
    MAG = "\033[35m"
    CYN = "\033[36m"
    WHT = "\033[37m"

    GRY = "\033[90m"
    BRED = "\033[91m"
    BGRN = "\033[92m"
    BYEL = "\033[93m"
    BBLU = "\033[94m"
    BMAG = "\033[95m"
    BCYN = "\033[96m"
    BWHT = "\033[97m"

    BG_RED = "\033[41m"
    BG_GRN = "\033[42m"
    BG_YEL = "\033[43m"
    BG_BLU = "\033[44m"
    BG_MAG = "\033[45m"
    BG_CYN = "\033[46m"
    BG_BLK = "\033[40m"

    # 256-color extras
    ORANGE = "\033[38;5;208m"
    PINK = "\033[38;5;213m"
    LIME = "\033[38;5;118m"
    TEAL = "\033[38;5;44m"
    PURPLE = "\033[38;5;99m"
    GOLD = "\033[38;5;220m"
    SALMON = "\033[38;5;209m"
    MINT = "\033[38;5;121m"
    ICE = "\033[38;5;159m"
    BLOOD = "\033[38;5;160m"
    NEON = "\033[38;5;46m"
    HOTPINK = "\033[38;5;198m"
    SKY = "\033[38;5;39m"
    VIOLET = "\033[38;5;135m"

    RAINBOW = (
        "\033[38;5;196m",
        "\033[38;5;202m",
        "\033[38;5;208m",
        "\033[38;5;220m",
        "\033[38;5;118m",
        "\033[38;5;48m",
        "\033[38;5;45m",
        "\033[38;5;39m",
        "\033[38;5;63m",
        "\033[38;5;99m",
        "\033[38;5;165m",
        "\033[38;5;199m",
    )


NO_COLOR = False


def use_color() -> bool:
    if NO_COLOR:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def c(code: str, text: Any) -> str:
    if not use_color():
        return str(text)
    return f"{code}{text}{C.RESET}"


def rainbow(text: str) -> str:
    if not use_color():
        return text
    out = []
    pal = C.RAINBOW
    i = 0
    for ch in text:
        if ch == " ":
            out.append(ch)
            continue
        out.append(f"{pal[i % len(pal)]}{ch}")
        i += 1
    out.append(C.RESET)
    return "".join(out)


def paint_line(text: str, offset: int = 0) -> str:
    if not use_color():
        return text
    pal = C.RAINBOW
    out = []
    for i, ch in enumerate(text):
        out.append(f"{pal[(i + offset) % len(pal)]}{ch}")
    out.append(C.RESET)
    return "".join(out)


def status_color(status: str | None) -> str:
    s = (status or "").lower()
    if s in {"online", "ok", "listed", "malicious"}:
        return C.BRED + C.BOLD
    if s in {"offline", "no_results"}:
        return C.GRY
    if s in {"unknown"}:
        return C.YEL
    return C.WHT


def threat_color(threat: str | None) -> str:
    t = (threat or "").lower()
    if "malware" in t or "botnet" in t or "c2" in t or "payload" in t:
        return C.HOTPINK
    if "phish" in t:
        return C.ORANGE
    return C.BCYN


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
BANNER_LINES = [
    r"   ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗  ██╗ █████╗ ██╗   ██╗███████╗",
    r"  ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║  ██║██╔══██╗██║   ██║██╔════╝",
    r"  ██║     ███████║██████╔╝██║   ██║██╔████╔██║███████║███████║███████║██║   ██║███████╗",
    r"  ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╔╝██║██╔══██║██╔══██║██╔══██║██║   ██║╚════██║",
    r"  ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██║╚██████╔╝███████║",
    r"   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
]

HOUSE = [
    r"            /\        ",
    r"           /  \       ",
    r"          /_██_\      ",
    r"         | ■  ■ |     ",
    r"         |  ▄▄  |     ",
    r"         |__██__|     ",
]


def print_banner() -> None:
    print()
    for i, line in enumerate(BANNER_LINES):
        print("  " + paint_line(line, offset=i * 2))
    print()
    print("  " + c(C.HOTPINK + C.BOLD, "▲") + " " + rainbow(NAME) + c(C.GRY, f"  v{VERSION}"))
    print("  " + c(C.DIM, TAGLINE))
    print("  " + c(C.PURPLE, "URLhaus") + c(C.GRY, " · ") + c(C.ORANGE, "MalwareBazaar")
          + c(C.GRY, " · ") + c(C.SKY, "ThreatFox") + c(C.GRY, " · ")
          + c(C.LIME, "Feodo") + c(C.GRY, " · ") + c(C.GOLD, "SSLBL"))
    print()


def print_mini_house() -> None:
    for i, line in enumerate(HOUSE):
        print("  " + paint_line(line, offset=i * 3))


# ---------------------------------------------------------------------------
# Auth + HTTP
# ---------------------------------------------------------------------------
def load_auth_key(cli_key: str | None) -> str | None:
    if cli_key:
        return cli_key.strip()
    env = os.environ.get("ABUSECH_AUTH_KEY") or os.environ.get("ABUSE_CH_KEY")
    if env:
        return env.strip()
    candidates = [
        os.path.expanduser("~/.config/chromahaus/auth.key"),
        os.path.expanduser("~/.chromahaus.key"),
        os.path.join(os.getcwd(), ".chromahaus.key"),
    ]
    for path in candidates:
        try:
            with open(path, encoding="utf-8") as fh:
                val = fh.read().strip()
            if val:
                return val
        except OSError:
            continue
    return None


def http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    timeout: int = 45,
) -> tuple[int, bytes, str]:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, body, ctype
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
        return exc.code, body, exc.headers.get("Content-Type", "") if exc.headers else ""
    except urllib.error.URLError as exc:
        raise RuntimeError(f"network error talking to {url}: {exc.reason}") from exc


def api_json(
    url: str,
    key: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
) -> Any:
    headers = {"Auth-Key": key}
    data = None
    if json_body is not None:
        raw = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
        data = raw
        method = "POST"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        method = "POST"
    status, body, ctype = http_request(url, method=method, headers=headers, data=data)
    text = body.decode("utf-8", errors="replace")
    if status == 401:
        raise RuntimeError(
            "401 unauthorized — Auth-Key missing or invalid. "
            f"Get a free key at {AUTH_PORTAL}"
        )
    if status == 429:
        raise RuntimeError("429 rate limited by abuse.ch — slow down and retry later")
    if status >= 400:
        snippet = text[:300].replace("\n", " ")
        raise RuntimeError(f"HTTP {status} from {url} — {snippet}")
    if "application/json" in ctype or text[:1] in "{[":
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"_raw": text, "query_status": "parse_error"}
    return {"_raw": text, "query_status": "ok"}


# ---------------------------------------------------------------------------
# Pretty printers
# ---------------------------------------------------------------------------
def hr(char: str = "─", width: int = 78) -> None:
    print(c(C.GRY, char * width))


def kv(key: str, value: Any, key_color: str = C.BCYN) -> None:
    if value is None or value == "" or value == []:
        value = c(C.GRY, "—")
    print(f"  {c(key_color, f'{key:<18}')} {value}")


def badge(text: str, color: str) -> str:
    if not use_color():
        return f"[{text}]"
    return f"{color}{C.BOLD} {text} {C.RESET}"


def tags_fmt(tags: Any) -> str:
    if not tags:
        return c(C.GRY, "—")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    pal = [C.HOTPINK, C.ORANGE, C.GOLD, C.LIME, C.TEAL, C.SKY, C.VIOLET, C.PINK]
    bits = []
    for i, t in enumerate(tags):
        bits.append(c(pal[i % len(pal)], f"#{t}"))
    return " ".join(bits)


def shorten(s: str | None, n: int = 72) -> str:
    if not s:
        return ""
    s = s.replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


def parse_dt(s: str | None) -> str:
    if not s:
        return "—"
    return str(s).replace("T", " ").replace(" UTC", "") + (" UTC" if "UTC" not in str(s) else "")


# ---------------------------------------------------------------------------
# URLhaus
# ---------------------------------------------------------------------------
def urlhaus_recent_urls(key: str, limit: int) -> dict[str, Any]:
    url = f"{URLHAUS}/urls/recent/"
    if limit:
        url = f"{URLHAUS}/urls/recent/limit/{int(limit)}/"
    return api_json(url, key)


def urlhaus_recent_payloads(key: str, limit: int) -> dict[str, Any]:
    url = f"{URLHAUS}/payloads/recent/"
    if limit:
        url = f"{URLHAUS}/payloads/recent/limit/{int(limit)}/"
    return api_json(url, key)


def urlhaus_url(key: str, url: str) -> dict[str, Any]:
    return api_json(f"{URLHAUS}/url/", key, form={"url": url})


def urlhaus_host(key: str, host: str) -> dict[str, Any]:
    return api_json(f"{URLHAUS}/host/", key, form={"host": host})


def urlhaus_payload(key: str, digest: str) -> dict[str, Any]:
    digest = digest.lower().strip()
    field = "md5_hash" if len(digest) == 32 else "sha256_hash"
    return api_json(f"{URLHAUS}/payload/", key, form={field: digest})


def urlhaus_tag(key: str, tag: str) -> dict[str, Any]:
    return api_json(f"{URLHAUS}/tag/", key, form={"tag": tag})


def urlhaus_signature(key: str, signature: str) -> dict[str, Any]:
    return api_json(f"{URLHAUS}/signature/", key, form={"signature": signature})


def print_url_row(item: dict[str, Any], idx: int | None = None) -> None:
    status = item.get("url_status") or item.get("status") or "?"
    st = badge(str(status).upper(), status_color(status) + C.BG_BLK)
    prefix = c(C.GRY, f"{idx:>3} ") if idx is not None else "    "
    url = item.get("url") or ""
    host = item.get("host") or ""
    threat = item.get("threat") or ""
    date = item.get("date_added") or item.get("firstseen") or ""
    print(f"{prefix}{st} {c(C.BWHT, shorten(url, 70))}")
    extra = [
        c(C.GRY, parse_dt(date)),
        c(threat_color(threat), threat) if threat else "",
        c(C.ICE, host) if host else "",
        tags_fmt(item.get("tags")),
    ]
    print("      " + "  ".join(x for x in extra if x))


def print_urlhaus_url_detail(data: dict[str, Any]) -> None:
    qs = data.get("query_status")
    if qs == "no_results":
        print(c(C.YEL, "  no hit in URLhaus"))
        return
    if qs != "ok":
        print(c(C.BRED, f"  query_status: {qs}"))
        return
    print(c(C.BOLD + C.HOTPINK, "  ▸ URLhaus URL"))
    kv("id", data.get("id"))
    kv("url", c(C.BWHT, data.get("url")))
    kv("status", badge(str(data.get("url_status", "?")).upper(),
                       status_color(data.get("url_status"))))
    kv("host", data.get("host"))
    kv("threat", c(threat_color(data.get("threat")), data.get("threat")))
    kv("added", parse_dt(data.get("date_added")))
    kv("last online", parse_dt(data.get("last_online")))
    kv("reporter", data.get("reporter"))
    kv("larted", data.get("larted"))
    kv("tags", tags_fmt(data.get("tags")))
    kv("reference", data.get("urlhaus_reference"))
    bl = data.get("blacklists") or {}
    if bl:
        kv("spamhaus DBL", bl.get("spamhaus_dbl"))
        kv("SURBL", bl.get("surbl"))
    payloads = data.get("payloads") or []
    if payloads:
        print()
        print(c(C.BOLD + C.ORANGE, f"  ▸ payloads ({len(payloads)})"))
        for p in payloads[:25]:
            sig = p.get("signature") or "unlabeled"
            sha = p.get("response_sha256") or p.get("sha256_hash") or ""
            print(
                f"    {c(C.GOLD, sig):<28} {c(C.GRY, p.get('file_type') or '')}  "
                f"{c(C.MINT, sha[:16] + '…' if sha else '—')}  "
                f"{c(C.GRY, p.get('firstseen') or '')}"
            )


def print_urlhaus_host_detail(data: dict[str, Any]) -> None:
    qs = data.get("query_status")
    if qs == "no_results":
        print(c(C.YEL, "  no hit in URLhaus for that host"))
        return
    if qs != "ok":
        print(c(C.BRED, f"  query_status: {qs}"))
        return
    print(c(C.BOLD + C.SKY, "  ▸ URLhaus host"))
    kv("host", data.get("host"))
    kv("first seen", parse_dt(data.get("firstseen")))
    kv("url count", data.get("url_count"))
    kv("reference", data.get("urlhaus_reference"))
    bl = data.get("blacklists") or {}
    if bl:
        kv("spamhaus DBL", bl.get("spamhaus_dbl"))
        kv("SURBL", bl.get("surbl"))
    urls = data.get("urls") or []
    print()
    print(c(C.BOLD + C.HOTPINK, f"  ▸ urls on host ({len(urls)})"))
    for i, u in enumerate(urls[:40], 1):
        print_url_row(u, i)
    if len(urls) > 40:
        print(c(C.GRY, f"      … {len(urls) - 40} more"))


def print_payload_detail(data: dict[str, Any], title: str = "URLhaus payload") -> None:
    qs = data.get("query_status")
    if qs == "no_results":
        print(c(C.YEL, f"  no hit in {title}"))
        return
    if qs != "ok":
        print(c(C.BRED, f"  query_status: {qs}"))
        return
    print(c(C.BOLD + C.ORANGE, f"  ▸ {title}"))
    kv("md5", data.get("md5_hash"))
    kv("sha256", data.get("sha256_hash"))
    kv("type", data.get("file_type"))
    kv("size", data.get("file_size"))
    kv("signature", c(C.GOLD, data.get("signature") or "unlabeled"))
    kv("first seen", parse_dt(data.get("firstseen")))
    kv("imphash", data.get("imphash"))
    kv("ssdeep", shorten(data.get("ssdeep"), 60) if data.get("ssdeep") else None)
    kv("tlsh", data.get("tlsh"))
    kv("magika", data.get("magika"))
    vt = data.get("virustotal")
    if isinstance(vt, dict):
        kv("virusTotal", f"{vt.get('result')} ({vt.get('percent')}%)")
    urls = data.get("urls") or []
    if urls:
        print()
        print(c(C.BOLD + C.HOTPINK, f"  ▸ distributing URLs ({len(urls)})"))
        for i, u in enumerate(urls[:20], 1):
            print_url_row(u, i)


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------
def bazaar(key: str, query: str, **params: Any) -> dict[str, Any]:
    form = {"query": query}
    form.update({k: str(v) for k, v in params.items() if v is not None})
    return api_json(BAZAAR, key, form=form)


def print_bazaar_samples(data: dict[str, Any], heading: str) -> None:
    qs = data.get("query_status")
    if qs not in {"ok", "success"}:
        print(c(C.YEL, f"  MalwareBazaar: {qs or 'no data'}"))
        if data.get("data") and isinstance(data["data"], str):
            print("  " + str(data["data"]))
        return
    rows = data.get("data") or []
    if isinstance(rows, dict):
        rows = [rows]
    print(c(C.BOLD + C.ORANGE, f"  ▸ {heading} ({len(rows)})"))
    for i, s in enumerate(rows[:40], 1):
        sig = s.get("signature") or s.get("malware") or "unlabeled"
        ftype = s.get("file_type") or s.get("file_type_mime") or ""
        sha = s.get("sha256_hash") or ""
        seen = s.get("first_seen") or s.get("firstseen") or ""
        tags = s.get("tags") or []
        print(
            f"  {c(C.GRY, f'{i:>3}')} {c(C.GOLD + C.BOLD, shorten(str(sig), 22)):<32} "
            f"{c(C.TEAL, str(ftype)[:10]):<12} {c(C.MINT, sha[:16] + '…' if sha else '—')}  "
            f"{c(C.GRY, seen)}"
        )
        if tags:
            print("       " + tags_fmt(tags))


def print_bazaar_info(data: dict[str, Any]) -> None:
    qs = data.get("query_status")
    if qs not in {"ok", "success"}:
        print(c(C.YEL, f"  MalwareBazaar: {qs or 'no hit'}"))
        return
    rows = data.get("data") or []
    if not rows:
        print(c(C.YEL, "  MalwareBazaar: empty data"))
        return
    s = rows[0]
    print(c(C.BOLD + C.ORANGE, "  ▸ MalwareBazaar sample"))
    kv("sha256", s.get("sha256_hash"))
    kv("sha1", s.get("sha1_hash"))
    kv("md5", s.get("md5_hash"))
    kv("signature", c(C.GOLD, s.get("signature") or "unlabeled"))
    kv("file type", s.get("file_type"))
    kv("mime", s.get("file_type_mime"))
    kv("size", s.get("file_size"))
    kv("first seen", s.get("first_seen"))
    kv("last seen", s.get("last_seen"))
    kv("delivery", s.get("delivery_method"))
    kv("origin", s.get("origin_country"))
    kv("reporter", s.get("reporter"))
    kv("tags", tags_fmt(s.get("tags")))
    intel = s.get("intelligence") or {}
    if intel:
        kv("downloads", intel.get("downloads"))
        kv("uploads", intel.get("uploads"))
        kv("clamav", intel.get("clamav"))
    yw = s.get("yara_rules") or s.get("yara") or []
    if yw:
        names = [y.get("rule_name") or y.get("rule") or str(y) for y in yw[:8]]
        kv("yara", ", ".join(names))
    print(c(C.DIM, f"  page  https://bazaar.abuse.ch/sample/{s.get('sha256_hash')}/"))


# ---------------------------------------------------------------------------
# ThreatFox
# ---------------------------------------------------------------------------
def threatfox(key: str, payload: dict[str, Any]) -> dict[str, Any]:
    return api_json(THREATFOX, key, json_body=payload)


def print_iocs(data: dict[str, Any], heading: str) -> None:
    qs = data.get("query_status")
    if qs != "ok":
        print(c(C.YEL, f"  ThreatFox: {qs or 'no data'}"))
        return
    rows = data.get("data") or []
    if isinstance(rows, dict):
        rows = [rows]
    print(c(C.BOLD + C.SKY, f"  ▸ {heading} ({len(rows)})"))
    for i, ioc in enumerate(rows[:50], 1):
        conf = ioc.get("confidence_level")
        try:
            conf_i = int(conf)
        except (TypeError, ValueError):
            conf_i = 0
        if conf_i >= 90:
            conf_s = c(C.NEON, f"{conf_i:>3}%")
        elif conf_i >= 50:
            conf_s = c(C.GOLD, f"{conf_i:>3}%")
        else:
            conf_s = c(C.GRY, f"{conf_i:>3}%")
        mal = ioc.get("malware") or ioc.get("malware_printable") or "?"
        kind = ioc.get("ioc_type") or ioc.get("threat_type") or ""
        val = ioc.get("ioc") or ""
        print(
            f"  {c(C.GRY, f'{i:>3}')} {conf_s}  {c(C.PINK, shorten(str(mal), 18)):<22} "
            f"{c(C.TEAL, str(kind)[:14]):<15} {c(C.BWHT, shorten(str(val), 48))}"
        )


# ---------------------------------------------------------------------------
# Feodo / SSLBL
# ---------------------------------------------------------------------------
def fetch_text_list(url: str, key: str) -> str:
    status, body, _ = http_request(url, headers={"Auth-Key": key})
    if status == 401:
        raise RuntimeError(f"401 unauthorized fetching {url}")
    if status >= 400:
        raise RuntimeError(f"HTTP {status} fetching {url}")
    return body.decode("utf-8", errors="replace")


def print_feodo(text: str, limit: int) -> None:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
    print(c(C.BOLD + C.LIME, f"  ▸ Feodo Tracker recommended C2 blocklist ({len(lines)} IPs)"))
    print(c(C.DIM, "    (dataset can be empty after large botnet disruptions)"))
    for i, ip in enumerate(lines[:limit], 1):
        print(f"  {c(C.GRY, f'{i:>3}')} {c(C.BRED, ip)}")
    if len(lines) > limit:
        print(c(C.GRY, f"      … {len(lines) - limit} more"))


def print_sslbl(text: str, limit: int) -> None:
    reader = csv.reader(io.StringIO(text))
    rows = []
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        rows.append(row)
    print(c(C.BOLD + C.GOLD, f"  ▸ SSL Blacklist entries ({len(rows)})"))
    for i, row in enumerate(rows[:limit], 1):
        listing = "  ".join(c(C.WHT, col) for col in row[:4])
        print(f"  {c(C.GRY, f'{i:>3}')} {listing}")
    if len(rows) > limit:
        print(c(C.GRY, f"      … {len(rows) - limit} more"))


# ---------------------------------------------------------------------------
# Hunt — auto-detect indicator type
# ---------------------------------------------------------------------------
HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$"
)


def classify(indicator: str) -> str:
    s = indicator.strip()
    if s.lower().startswith(("http://", "https://")):
        return "url"
    if HASH_RE.match(s):
        return "hash"
    if IPV4_RE.match(s):
        return "ip"
    if DOMAIN_RE.match(s):
        return "host"
    return "term"


def cmd_hunt(key: str, indicator: str, raw: bool) -> None:
    kind = classify(indicator)
    print(c(C.BOLD, "  hunting ") + c(C.BWHT, indicator) + c(C.GRY, f"  (detected: {kind})"))
    hr()
    if kind == "url":
        dump_or_pretty(urlhaus_url(key, indicator), raw, lambda d: print_urlhaus_url_detail(d))
        print()
        dump_or_pretty(
            threatfox(key, {"query": "search_ioc", "search_term": indicator}),
            raw,
            lambda d: print_iocs(d, "ThreatFox URL / related IOCs"),
        )
    elif kind == "hash":
        dump_or_pretty(urlhaus_payload(key, indicator), raw, lambda d: print_payload_detail(d))
        print()
        dump_or_pretty(bazaar(key, "get_info", hash=indicator), raw, print_bazaar_info)
        print()
        dump_or_pretty(
            threatfox(key, {"query": "search_hash", "hash": indicator}),
            raw,
            lambda d: print_iocs(d, "ThreatFox hash hits"),
        )
    elif kind in {"ip", "host"}:
        host = indicator.split(":")[0]
        dump_or_pretty(urlhaus_host(key, host), raw, print_urlhaus_host_detail)
        print()
        dump_or_pretty(
            threatfox(key, {"query": "search_ioc", "search_term": indicator}),
            raw,
            lambda d: print_iocs(d, "ThreatFox IOC hits"),
        )
    else:
        dump_or_pretty(urlhaus_tag(key, indicator), raw, lambda d: _print_tag_or_sig(d, "tag"))
        print()
        dump_or_pretty(
            threatfox(key, {"query": "search_ioc", "search_term": indicator}),
            raw,
            lambda d: print_iocs(d, "ThreatFox search"),
        )
        print()
        dump_or_pretty(
            bazaar(key, "get_taginfo", tag=indicator, limit=25),
            raw,
            lambda d: print_bazaar_samples(d, f"MalwareBazaar tag:{indicator}"),
        )


def _print_tag_or_sig(data: dict[str, Any], kind: str) -> None:
    qs = data.get("query_status")
    if qs != "ok":
        print(c(C.YEL, f"  URLhaus {kind}: {qs or 'no hit'}"))
        return
    print(c(C.BOLD + C.VIOLET, f"  ▸ URLhaus {kind} {data.get(kind) or ''}"))
    kv("first seen", data.get("firstseen"))
    kv("url count", data.get("url_count"))
    urls = data.get("urls") or []
    for i, u in enumerate(urls[:30], 1):
        print_url_row(u, i)


def dump_or_pretty(data: Any, raw: bool, pretty) -> None:
    if raw:
        print(json.dumps(data, indent=2, default=str))
    else:
        pretty(data)


# ---------------------------------------------------------------------------
# Watch feed
# ---------------------------------------------------------------------------
def cmd_watch(key: str, interval: int, limit: int) -> None:
    print(c(C.BOLD + C.HOTPINK, f"  live URLhaus feed — every {interval}s  (Ctrl-C to stop)"))
    seen: set[str] = set()
    first = True
    try:
        while True:
            data = urlhaus_recent_urls(key, limit)
            urls = data.get("urls") or []
            fresh = []
            for u in urls:
                uid = str(u.get("id") or u.get("url"))
                if uid not in seen:
                    fresh.append(u)
                    seen.add(uid)
            stamp = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            if first:
                print(c(C.GRY, f"  [{stamp}] primed with {len(seen)} recent URLs"))
                first = False
            elif fresh:
                print(c(C.NEON + C.BOLD, f"  [{stamp}] +{len(fresh)} new"))
                for i, u in enumerate(fresh, 1):
                    print_url_row(u, i)
            else:
                print(c(C.GRY, f"  [{stamp}] quiet"))
            time.sleep(max(15, interval))
    except KeyboardInterrupt:
        print("\n" + c(C.GRY, "  stopped watching"))


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
def export_rows(path: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        print(c(C.YEL, "  nothing to export"))
        return
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2, default=str)
    else:
        keys: list[str] = []
        for row in rows:
            for k in row:
                if k not in keys:
                    keys.append(k)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
            w.writeheader()
            for row in rows:
                flat = {}
                for k, v in row.items():
                    if isinstance(v, (list, dict)):
                        flat[k] = json.dumps(v, default=str)
                    else:
                        flat[k] = v
                w.writerow(flat)
    print(c(C.BGRN, f"  wrote {len(rows)} rows → {path}"))


# ---------------------------------------------------------------------------
# Sample download (explicit, warned)
# ---------------------------------------------------------------------------
def cmd_download(key: str, sha256: str, dest: str, i_understand: bool) -> None:
    sha256 = sha256.lower().strip()
    if len(sha256) != 64 or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise SystemExit("need a SHA256 (64 hex chars)")
    print()
    print(c(C.BG_RED + C.BWHT + C.BOLD, "  LIVE MALWARE  "))
    print(c(C.BRED, "  This fetches a real sample from abuse.ch."))
    print(c(C.BRED, "  Archives are typically ZIP password: ") + c(C.GOLD, SAMPLE_ZIP_PASSWORD))
    print(c(C.YEL, "  Never open or run this on a production / personal machine."))
    print(c(C.YEL, "  Isolated VM, no shared folders, snapshots on. You have been warned."))
    print()
    if not i_understand:
        raise SystemExit("refusing to download — pass --i-understand if you really mean it")
    dest_dir = dest or os.getcwd()
    os.makedirs(dest_dir, exist_ok=True)
    out = os.path.join(dest_dir, f"{sha256}.zip")
    url = f"{URLHAUS}/download/{sha256}/"
    status, body, ctype = http_request(url, headers={"Auth-Key": key})
    if status >= 400 or len(body) < 32:
        # fallback to MalwareBazaar get_file
        print(c(C.GRY, "  URLhaus download missed, trying MalwareBazaar…"))
        form = urllib.parse.urlencode({"query": "get_file", "sha256_hash": sha256}).encode()
        status, body, ctype = http_request(
            BAZAAR,
            method="POST",
            headers={"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded"},
            data=form,
        )
    if status >= 400:
        raise SystemExit(f"download failed HTTP {status}")
    # JSON error body?
    if body[:1] == b"{":
        try:
            err = json.loads(body.decode("utf-8", errors="replace"))
            raise SystemExit(f"API said: {err}")
        except json.JSONDecodeError:
            pass
    with open(out, "wb") as fh:
        fh.write(body)
    print(c(C.BGRN, f"  saved {len(body)} bytes → {out}"))
    print(c(C.GRY, f"  zip password is usually '{SAMPLE_ZIP_PASSWORD}'"))


# ---------------------------------------------------------------------------
# Interactive REPL
# ---------------------------------------------------------------------------
HELP_TEXT = f"""
{NAME} commands
  hunt <indicator>     auto-detect URL / host / IP / hash / tag and query all feeds
  url <url>            URLhaus lookup for a specific URL
  host <host|ip>       URLhaus host report
  hash <md5|sha256>    payload + bazaar + threatfox
  recent [n]           latest malware URLs (default 25)
  payloads [n]         latest URLhaus payloads
  tag <tag>            URLhaus + bazaar by tag (emotet, mozi, …)
  family <name>        URLhaus signature + threatfox malwareinfo + bazaar sig
  iocs [days]          recent ThreatFox IOCs (1-7 days)
  fox <term>           ThreatFox IOC search
  bazaar [n]           latest MalwareBazaar samples
  feodo                Feodo Tracker recommended C2 IPs
  sslbl                SSL certificate blacklist
  watch [sec]          poll URLhaus recent URLs
  download <sha256>    fetch sample zip (needs --i-understand)
  export <file>        dump last result as .json / .csv
  raw                  toggle raw JSON
  help                 this text
  quit                 leave the house
"""


def repl(key: str) -> None:
    print_banner()
    print_mini_house()
    print(c(C.GRY, "  type ") + c(C.BWHT, "help") + c(C.GRY, "  ·  indicators can also be pasted bare"))
    print()
    raw = False
    last_rows: list[dict[str, Any]] = []
    while True:
        try:
            prompt = rainbow("chroma") + c(C.HOTPINK, "⌂ ")
            line = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        try:
            if cmd in {"q", "quit", "exit"}:
                break
            if cmd in {"help", "?"}:
                print(HELP_TEXT)
            elif cmd == "raw":
                raw = not raw
                print(c(C.GOLD, f"  raw JSON {'on' if raw else 'off'}"))
            elif cmd == "hunt" and arg:
                cmd_hunt(key, arg, raw)
            elif cmd == "url" and arg:
                data = urlhaus_url(key, arg)
                last_rows = [data]
                dump_or_pretty(data, raw, print_urlhaus_url_detail)
            elif cmd == "host" and arg:
                data = urlhaus_host(key, arg)
                last_rows = data.get("urls") or [data]
                dump_or_pretty(data, raw, print_urlhaus_host_detail)
            elif cmd == "hash" and arg:
                cmd_hunt(key, arg, raw)
            elif cmd == "recent":
                n = int(arg) if arg else 25
                data = urlhaus_recent_urls(key, n)
                last_rows = data.get("urls") or []
                if raw:
                    print(json.dumps(data, indent=2))
                else:
                    print(c(C.BOLD + C.HOTPINK, f"  ▸ recent URLhaus URLs ({len(last_rows)})"))
                    for i, u in enumerate(last_rows[:n], 1):
                        print_url_row(u, i)
            elif cmd == "payloads":
                n = int(arg) if arg else 25
                data = urlhaus_recent_payloads(key, n)
                last_rows = data.get("payloads") or []
                dump_or_pretty(
                    data,
                    raw,
                    lambda d: _print_recent_payloads(d, n),
                )
            elif cmd == "tag" and arg:
                dump_or_pretty(urlhaus_tag(key, arg), raw, lambda d: _print_tag_or_sig(d, "tag"))
                print()
                dump_or_pretty(
                    bazaar(key, "get_taginfo", tag=arg, limit=25),
                    raw,
                    lambda d: print_bazaar_samples(d, f"bazaar tag:{arg}"),
                )
            elif cmd in {"family", "sig", "signature"} and arg:
                dump_or_pretty(
                    urlhaus_signature(key, arg),
                    raw,
                    lambda d: _print_tag_or_sig(d, "signature"),
                )
                print()
                dump_or_pretty(
                    threatfox(key, {"query": "malwareinfo", "malware": arg, "limit": 50}),
                    raw,
                    lambda d: print_iocs(d, f"ThreatFox {arg}"),
                )
                print()
                dump_or_pretty(
                    bazaar(key, "get_siginfo", signature=arg, limit=25),
                    raw,
                    lambda d: print_bazaar_samples(d, f"bazaar sig:{arg}"),
                )
            elif cmd == "iocs":
                days = int(arg) if arg else 1
                days = min(max(days, 1), 7)
                data = threatfox(key, {"query": "get_iocs", "days": days})
                last_rows = data.get("data") or []
                dump_or_pretty(data, raw, lambda d: print_iocs(d, f"ThreatFox last {days}d"))
            elif cmd == "fox" and arg:
                data = threatfox(key, {"query": "search_ioc", "search_term": arg})
                last_rows = data.get("data") or []
                dump_or_pretty(data, raw, lambda d: print_iocs(d, f"ThreatFox '{arg}'"))
            elif cmd == "bazaar":
                n = int(arg) if arg else 25
                data = bazaar(key, "get_recent", selector=str(n))
                last_rows = data.get("data") or []
                dump_or_pretty(data, raw, lambda d: print_bazaar_samples(d, "latest bazaar samples"))
            elif cmd == "feodo":
                text = fetch_text_list(FEODO_REC, key)
                print_feodo(text, 40)
            elif cmd == "sslbl":
                text = fetch_text_list(SSLBL, key)
                print_sslbl(text, 30)
            elif cmd == "watch":
                sec = int(arg) if arg else 30
                cmd_watch(key, sec, 50)
            elif cmd == "download" and arg:
                cmd_download(key, arg.split()[0], ".", False)
            elif cmd == "export" and arg:
                export_rows(arg, last_rows if isinstance(last_rows, list) else [last_rows])
            elif classify(cmd if not arg else f"{cmd} {arg}") != "term" and not arg:
                cmd_hunt(key, cmd, raw)
            elif arg and classify(line) != "term":
                cmd_hunt(key, line, raw)
            else:
                print(c(C.YEL, "  unknown command — type help"))
        except Exception as exc:
            print(c(C.BRED, f"  ! {exc}"))
    print(c(C.GRY, "  doors locked. stay curious, stay careful."))


def _print_recent_payloads(data: dict[str, Any], n: int) -> None:
    rows = data.get("payloads") or []
    print(c(C.BOLD + C.ORANGE, f"  ▸ recent payloads ({len(rows)})"))
    for i, p in enumerate(rows[:n], 1):
        sig = p.get("signature") or "unlabeled"
        sha = p.get("sha256_hash") or ""
        print(
            f"  {c(C.GRY, f'{i:>3}')} {c(C.GOLD, shorten(str(sig), 20)):<24} "
            f"{c(C.TEAL, str(p.get('file_type') or '')[:8]):<10} "
            f"{c(C.MINT, sha[:18] + '…' if sha else '—')}  "
            f"{c(C.GRY, p.get('firstseen') or '')}"
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chromahaus",
        description=f"{NAME} — {TAGLINE}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""examples:
  export ABUSECH_AUTH_KEY='…'          # https://auth.abuse.ch/
  python3 chromahaus.py                # interactive
  python3 chromahaus.py recent -n 15
  python3 chromahaus.py hunt http://example.invalid/payload.exe
  python3 chromahaus.py hunt 8.8.8.8
  python3 chromahaus.py family emotes
  python3 chromahaus.py watch --interval 45
  python3 chromahaus.py download <sha256> --i-understand

docs: {DOCS['urlhaus']}
""",
    )
    p.add_argument("--key", help="abuse.ch Auth-Key (else $ABUSECH_AUTH_KEY or key file)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--json", action="store_true", dest="raw", help="print raw JSON")
    p.add_argument("--out", help="export last listing to .json or .csv")
    p.add_argument("-n", "--limit", type=int, default=25, help="row cap for list commands")
    p.add_argument("-V", "--version", action="version", version=f"{NAME} {VERSION}")

    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("repl", help="interactive shell (default)")

    h = sub.add_parser("hunt", help="auto-detect indicator and query every feed")
    h.add_argument("indicator")

    u = sub.add_parser("url", help="URLhaus URL lookup")
    u.add_argument("value")

    ho = sub.add_parser("host", help="URLhaus host / IP lookup")
    ho.add_argument("value")

    ha = sub.add_parser("hash", help="hash lookup across URLhaus + Bazaar + ThreatFox")
    ha.add_argument("value")

    sub.add_parser("recent", help="latest malware URLs")
    sub.add_parser("payloads", help="latest URLhaus payloads")

    t = sub.add_parser("tag", help="search by tag")
    t.add_argument("value")

    f = sub.add_parser("family", help="malware family / signature")
    f.add_argument("value")

    i = sub.add_parser("iocs", help="recent ThreatFox IOCs")
    i.add_argument("--days", type=int, default=1)

    fx = sub.add_parser("fox", help="ThreatFox IOC search")
    fx.add_argument("value")

    sub.add_parser("bazaar", help="latest MalwareBazaar samples")
    sub.add_parser("feodo", help="Feodo Tracker C2 IPs")
    sub.add_parser("sslbl", help="SSL blacklist")

    w = sub.add_parser("watch", help="live poll of new URLhaus URLs")
    w.add_argument("--interval", type=int, default=30)

    d = sub.add_parser("download", help="download a sample zip (dangerous)")
    d.add_argument("sha256")
    d.add_argument("--dest", default=".")
    d.add_argument("--i-understand", action="store_true")

    return p


def require_key(key: str | None) -> str:
    if key:
        return key
    print(c(C.BRED + C.BOLD, "  no Auth-Key found"))
    print(c(C.WHT, "  abuse.ch made community API keys mandatory."))
    print(c(C.WHT, f"  1. create a free key at {AUTH_PORTAL}"))
    print(c(C.WHT, "  2. export ABUSECH_AUTH_KEY='…'"))
    print(c(C.WHT, "     or: python3 chromahaus.py --key YOUR-KEY recent"))
    print(c(C.WHT, "     or: mkdir -p ~/.config/chromahaus && echo KEY > ~/.config/chromahaus/auth.key"))
    raise SystemExit(2)


def main(argv: list[str] | None = None) -> int:
    global NO_COLOR
    args = build_parser().parse_args(argv)
    NO_COLOR = bool(args.no_color)
    key = load_auth_key(args.key)

    if not args.cmd:
        key = require_key(key)
        repl(key)
        return 0

    key = require_key(key)
    raw = args.raw
    limit = args.limit
    last_rows: list[dict[str, Any]] = []

    try:
        if args.cmd == "repl":
            repl(key)
            return 0
        if args.cmd != "watch":
            print_banner()

        if args.cmd == "hunt":
            cmd_hunt(key, args.indicator, raw)
        elif args.cmd == "url":
            data = urlhaus_url(key, args.value)
            last_rows = [data]
            dump_or_pretty(data, raw, print_urlhaus_url_detail)
        elif args.cmd == "host":
            data = urlhaus_host(key, args.value)
            last_rows = data.get("urls") or [data]
            dump_or_pretty(data, raw, print_urlhaus_host_detail)
        elif args.cmd == "hash":
            cmd_hunt(key, args.value, raw)
        elif args.cmd == "recent":
            data = urlhaus_recent_urls(key, limit)
            last_rows = data.get("urls") or []
            if raw:
                print(json.dumps(data, indent=2))
            else:
                print(c(C.BOLD + C.HOTPINK, f"  ▸ recent URLhaus URLs ({len(last_rows)})"))
                for i, u in enumerate(last_rows[:limit], 1):
                    print_url_row(u, i)
        elif args.cmd == "payloads":
            data = urlhaus_recent_payloads(key, limit)
            last_rows = data.get("payloads") or []
            dump_or_pretty(data, raw, lambda d: _print_recent_payloads(d, limit))
        elif args.cmd == "tag":
            dump_or_pretty(urlhaus_tag(key, args.value), raw, lambda d: _print_tag_or_sig(d, "tag"))
            print()
            b = bazaar(key, "get_taginfo", tag=args.value, limit=limit)
            last_rows = b.get("data") or []
            dump_or_pretty(b, raw, lambda d: print_bazaar_samples(d, f"bazaar tag:{args.value}"))
        elif args.cmd == "family":
            dump_or_pretty(
                urlhaus_signature(key, args.value),
                raw,
                lambda d: _print_tag_or_sig(d, "signature"),
            )
            print()
            dump_or_pretty(
                threatfox(key, {"query": "malwareinfo", "malware": args.value, "limit": limit}),
                raw,
                lambda d: print_iocs(d, f"ThreatFox {args.value}"),
            )
            print()
            dump_or_pretty(
                bazaar(key, "get_siginfo", signature=args.value, limit=limit),
                raw,
                lambda d: print_bazaar_samples(d, f"bazaar sig:{args.value}"),
            )
        elif args.cmd == "iocs":
            days = min(max(args.days, 1), 7)
            data = threatfox(key, {"query": "get_iocs", "days": days})
            last_rows = data.get("data") or []
            dump_or_pretty(data, raw, lambda d: print_iocs(d, f"ThreatFox last {days}d"))
        elif args.cmd == "fox":
            data = threatfox(key, {"query": "search_ioc", "search_term": args.value})
            last_rows = data.get("data") or []
            dump_or_pretty(data, raw, lambda d: print_iocs(d, f"ThreatFox '{args.value}'"))
        elif args.cmd == "bazaar":
            data = bazaar(key, "get_recent", selector=str(limit))
            last_rows = data.get("data") or []
            dump_or_pretty(data, raw, lambda d: print_bazaar_samples(d, "latest bazaar samples"))
        elif args.cmd == "feodo":
            print_feodo(fetch_text_list(FEODO_REC, key), limit)
        elif args.cmd == "sslbl":
            print_sslbl(fetch_text_list(SSLBL, key), limit)
        elif args.cmd == "watch":
            cmd_watch(key, args.interval, limit)
        elif args.cmd == "download":
            cmd_download(key, args.sha256, args.dest, args.i_understand)
        else:
            raise SystemExit(f"unknown command {args.cmd}")

        if args.out and last_rows:
            export_rows(args.out, last_rows)
    except Exception as exc:
        print(c(C.BRED, f"  ! {exc}"), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
