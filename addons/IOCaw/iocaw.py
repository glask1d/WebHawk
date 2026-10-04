#!/usr/bin/env python3
"""
IOCaw — a colorful CLI hunter for the public TweetFeed.live IOC API.

TweetFeed aggregates indicators of compromise shared by infosec researchers
on X/Twitter (URLs, domains, IPs, MD5, SHA-256). Data is CC0. This tool
queries the open REST API; it does not visit, execute, or verify the IOCs.

    python3 iocaw.py feed today --tag phishing --type url
    python3 iocaw.py lookup evil.example
    python3 iocaw.py campaigns
    python3 iocaw.py trends
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

NAME = "IOCaw"
VERSION = "1.0.0"
BASE = "https://api.tweetfeed.live"
DOCS = "https://tweetfeed.live/api/"
USER_AGENT = f"{NAME}/{VERSION} (+https://tweetfeed.live; research CLI)"
TIMEOUT = 30

WINDOWS = ("today", "week", "month", "year")
IOC_TYPES = ("url", "domain", "ip", "sha256", "md5")

TYPE_STYLE = {
    "url": "bright_cyan",
    "domain": "bright_blue",
    "ip": "bright_magenta",
    "sha256": "yellow",
    "md5": "gold1",
}

TAG_STYLE = {
    "phishing": "bright_red",
    "scam": "red",
    "cryptoscam": "red",
    "malware": "bright_yellow",
    "ransomware": "dark_orange",
    "stealer": "orange1",
    "infostealer": "orange1",
    "c2": "bright_magenta",
    "apt": "medium_purple1",
    "rat": "orchid",
}

theme = Theme(
    {
        "info": "cyan",
        "warn": "bold yellow",
        "err": "bold red",
        "ok": "bold green",
        "muted": "dim",
        "head": "bold bright_white",
        "accent": "bold bright_cyan",
        "caw": "bold bright_yellow",
    }
)
console = Console(theme=theme, highlight=False)


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

class TweetFeedError(RuntimeError):
    pass


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/csv, text/plain;q=0.8, */*;q=0.5",
        }
    )
    return s


SESSION = _session()


def api_get(
    path: str,
    params: dict[str, Any] | None = None,
    *,
    allow_redirects: bool = True,
    expect_json: bool = True,
) -> tuple[Any, requests.Response]:
    url = path if path.startswith("http") else f"{BASE}{path}"
    try:
        resp = SESSION.get(
            url, params=params, timeout=TIMEOUT, allow_redirects=allow_redirects
        )
    except requests.RequestException as exc:
        raise TweetFeedError(f"network error talking to TweetFeed: {exc}") from exc

    if resp.status_code == 410:
        raise TweetFeedError("410 Gone — timestamp is older than the 365-day horizon")
    if resp.status_code == 404:
        raise TweetFeedError(f"404 not found: {resp.url}")
    if resp.status_code == 403:
        raise TweetFeedError(
            "403 from Cloudflare. TweetFeed blocks bare urllib User-Agents; "
            "this client already sends a custom UA — retry in a moment."
        )
    if resp.status_code >= 400:
        snippet = (resp.text or "")[:240].replace("\n", " ")
        raise TweetFeedError(f"HTTP {resp.status_code} from {resp.url} — {snippet}")

    if not expect_json:
        return resp.text, resp

    ctype = (resp.headers.get("content-type") or "").lower()
    if "json" in ctype or resp.text[:1] in "[{":
        try:
            return resp.json(), resp
        except json.JSONDecodeError as exc:
            raise TweetFeedError(f"invalid JSON from {resp.url}: {exc}") from exc
    return resp.text, resp


def build_feed_path(window: str, filters: list[str]) -> str:
    parts = ["/v1", window]
    for f in filters:
        if f:
            parts.append(f.lstrip("/"))
    return "/".join(parts)


# ---------------------------------------------------------------------------
# Pretty helpers
# ---------------------------------------------------------------------------

BANNER = r"""
 _____ _____ _____                
|_   _|  _  /  __ \               
  | | | | | | /  \/ __ ___      __
  | | | | | | |    / _` \ \ /\ / /
 _| |_\ \_/ / \__/\ (_| |\ V  V / 
 \___/ \___/ \____/\__,_| \_/\_/  
                                  
                                  

   community IOC hunter  ·  tweetfeed.live  ·  CC0
"""


def print_banner() -> None:
    console.print(Text(BANNER, style="accent"))


def style_type(t: str) -> Text:
    return Text(t, style=TYPE_STYLE.get(t.lower(), "white"))


def style_tag(tag: str) -> Text:
    raw = tag.lstrip("#")
    style = TAG_STYLE.get(raw.lower(), "bright_white")
    return Text("#" + raw if not tag.startswith("#") else tag, style=style)


def style_tags(tags: list[str] | None) -> Text:
    out = Text()
    if not tags:
        return Text("—", style="muted")
    for i, tag in enumerate(tags):
        if i:
            out.append(" ")
        out.append_text(style_tag(str(tag)))
    return out


def defang_value(value: str, ioc_type: str | None = None) -> str:
    v = value or ""
    v = (
        v.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace("https:", "hxxps:")
        .replace("http:", "hxxp:")
    )
    # IPv4 / dotted hostnames
    if ioc_type == "ip" or _looks_like_ipv4(v):
        return v.replace(".", "[.]")
    # domains / urls: only defang dots in the host-ish portion
    return v.replace(".", "[.]")


def _looks_like_ipv4(v: str) -> bool:
    parts = v.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def display_value(value: str, ioc_type: str | None, defang: bool) -> str:
    return defang_value(value, ioc_type) if defang else value


def meta_line(resp: requests.Response) -> Text:
    h = resp.headers
    bits = []
    if h.get("X-Result-Count"):
        bits.append(f"count={h['X-Result-Count']}")
    if h.get("X-Result-Window-Start"):
        bits.append(f"from={h['X-Result-Window-Start']}")
    if h.get("X-Result-Window-End"):
        bits.append(f"to={h['X-Result-Window-End']}")
    if (h.get("X-Result-Truncated") or "").lower() == "true":
        bits.append("TRUNCATED@10k")
    if h.get("X-Resp-State"):
        bits.append(f"cache={h['X-Resp-State']}")
    text = Text("  ".join(bits) if bits else "ok", style="muted")
    return text


def ioc_table(rows: list[dict[str, Any]], *, defang: bool, limit: int | None) -> Table:
    table = Table(
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        pad_edge=False,
        header_style="head",
        expand=True,
    )
    table.add_column("when", style="muted", no_wrap=True)
    table.add_column("type", no_wrap=True)
    table.add_column("value", overflow="fold", min_width=24)
    table.add_column("tags", overflow="fold")
    table.add_column("by", style="bright_white", no_wrap=True)
    shown = rows[:limit] if limit else rows
    for row in shown:
        table.add_row(
            str(row.get("date") or "—"),
            style_type(str(row.get("type") or "?")),
            display_value(str(row.get("value") or ""), row.get("type"), defang),
            style_tags(row.get("tags") or []),
            "@" + str(row.get("user") or "?").lstrip("@"),
        )
    return table


def summarize(rows: list[dict[str, Any]]) -> None:
    types = Counter(str(r.get("type") or "?") for r in rows)
    tags: Counter[str] = Counter()
    users: Counter[str] = Counter()
    for r in rows:
        for t in r.get("tags") or []:
            tags[str(t).lstrip("#").lower()] += 1
        if r.get("user"):
            users[str(r["user"]).lstrip("@")] += 1
    parts = [f"[ok]{len(rows)}[/ok] IOCs"]
    for t, n in types.most_common():
        parts.append(f"[{TYPE_STYLE.get(t, 'white')}]{t}[/] {n}")
    console.print(" · ".join(parts))
    if tags:
        top = ", ".join(f"#{t} ({n})" for t, n in tags.most_common(8))
        console.print(f"[muted]top tags:[/muted] {top}")
    if users:
        top_u = ", ".join(f"@{u} ({n})" for u, n in users.most_common(5))
        console.print(f"[muted]top reporters:[/muted] {top_u}")


def export_rows(rows: list[dict[str, Any]], path: str) -> None:
    lower = path.lower()
    if lower.endswith(".json"):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
    elif lower.endswith(".txt"):
        with open(path, "w", encoding="utf-8") as fh:
            for r in rows:
                fh.write(str(r.get("value") or "") + "\n")
    else:
        if not lower.endswith(".csv"):
            path = path + ".csv"
        fields = ["date", "user", "type", "value", "tags", "tweet"]
        with open(path, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow(
                    {
                        "date": r.get("date", ""),
                        "user": r.get("user", ""),
                        "type": r.get("type", ""),
                        "value": r.get("value", ""),
                        "tags": " ".join(r.get("tags") or []),
                        "tweet": r.get("tweet", ""),
                    }
                )
    console.print(f"[ok]wrote[/ok] {path}")


def parse_csv_iocs(text: str) -> list[dict[str, Any]]:
    """TweetFeed year.csv columns: date, user, type, value, tags, tweet."""
    rows: list[dict[str, Any]] = []
    reader = csv.reader(io.StringIO(text))
    header = next(reader, None)
    if not header:
        return rows
    # detect header vs first data row
    looks_header = any(h.lower() in {"date", "user", "type", "value"} for h in header)
    if not looks_header:
        rows.append(_csv_row(header))
    for raw in reader:
        if raw:
            rows.append(_csv_row(raw))
    return rows


def _csv_row(raw: list[str]) -> dict[str, Any]:
    # date,user,type,value,tags,tweet  — tags often pipe or space separated
    date = raw[0] if len(raw) > 0 else ""
    user = raw[1] if len(raw) > 1 else ""
    typ = raw[2] if len(raw) > 2 else ""
    value = raw[3] if len(raw) > 3 else ""
    tags_raw = raw[4] if len(raw) > 4 else ""
    tweet = raw[5] if len(raw) > 5 else ""
    tags = [t for t in tags_raw.replace(",", " ").replace("|", " ").split() if t]
    return {
        "date": date,
        "user": user,
        "type": typ,
        "value": value,
        "tags": tags,
        "tweet": tweet,
    }


def local_match(row: dict[str, Any], needle: str) -> bool:
    n = needle.lower()
    blob = " ".join(
        [
            str(row.get("value") or ""),
            str(row.get("user") or ""),
            str(row.get("type") or ""),
            str(row.get("tweet") or ""),
            " ".join(row.get("tags") or []),
        ]
    ).lower()
    return n in blob


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_feed(args: argparse.Namespace) -> int:
    filters = [f for f in (args.tag, args.user, args.type) if f]
    # user handles should keep @
    if args.user and not args.user.startswith("@") and args.user not in IOC_TYPES:
        filters = [f if f != args.user else "@" + args.user for f in filters]

    if args.window == "year":
        console.print(
            "[warn]year window is a CSV redirect (unfiltered, last 365 days). "
            "Filters are applied client-side.[/warn]"
        )
        text, resp = api_get("/v1/year", expect_json=False)
        rows = parse_csv_iocs(text)
        if args.type:
            rows = [r for r in rows if str(r.get("type", "")).lower() == args.type.lower()]
        if args.tag:
            needle = args.tag.lstrip("#").lower()
            rows = [
                r
                for r in rows
                if any(needle == str(t).lstrip("#").lower() for t in (r.get("tags") or []))
            ]
        if args.user:
            u = args.user.lstrip("@").lower()
            rows = [r for r in rows if str(r.get("user", "")).lstrip("@").lower() == u]
    else:
        path = build_feed_path(args.window, filters)
        data, resp = api_get(path)
        if not isinstance(data, list):
            raise TweetFeedError(f"expected a JSON array from {path}, got {type(data).__name__}")
        rows = data

    if args.contains:
        rows = [r for r in rows if local_match(r, args.contains)]

    if args.json:
        payload = rows[: args.limit] if args.limit else rows
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        return 0

    console.print(
        Panel(
            f"[head]{args.window}[/head]  filters=[accent]{' / '.join(filters) or 'none'}[/accent]",
            subtitle=str(meta_line(resp)),
            border_style="cyan",
        )
    )

    if args.values_only:
        shown = rows[: args.limit] if args.limit else rows
        for r in shown:
            console.print(display_value(str(r.get("value") or ""), r.get("type"), args.defang))
        if args.export:
            export_rows(rows if not args.limit else rows[: args.limit], args.export)
        return 0

    if not rows:
        console.print("[warn]no IOCs matched.[/warn]")
        return 0

    console.print(ioc_table(rows, defang=args.defang, limit=args.limit))
    summarize(rows)
    if args.limit and len(rows) > args.limit:
        console.print(f"[muted]showing {args.limit} of {len(rows)} — raise --limit or drop it[/muted]")
    if args.tweets:
        shown = rows[: args.limit] if args.limit else rows
        console.print("\n[head]source tweets[/head]")
        for r in shown:
            if r.get("tweet"):
                console.print(f"  [muted]{r.get('value')}[/muted]  {r['tweet']}")
    if args.export:
        export_rows(rows if not args.limit else rows[: args.limit], args.export)
    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    data, _resp = api_get("/v1/ioc", {"value": args.value})
    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    found = bool(data.get("found"))
    title = f"lookup  [accent]{data.get('query', args.value)}[/accent]"
    border = "green" if found else "yellow"
    console.print(Panel(title, border_style=border))

    if not found:
        console.print("[warn]not found in the live 365-day window.[/warn]")
    else:
        console.print(f"[ok]found[/ok]  window={data.get('window', '365d')}")

    ai = data.get("ai") or {}
    if ai.get("summary"):
        console.print(
            Panel(
                f"{ai['summary']}\n\n"
                f"[muted]family={ai.get('family') or '—'}  "
                f"type={ai.get('threat_type') or '—'}  "
                f"confidence={ai.get('confidence')}[/muted]",
                title="AI context",
                border_style="magenta",
            )
        )

    records = data.get("records") or []
    if records:
        table = Table(box=box.SIMPLE_HEAVY, header_style="head", expand=True)
        table.add_column("type", no_wrap=True)
        table.add_column("value", overflow="fold")
        table.add_column("first seen", no_wrap=True)
        table.add_column("last seen", no_wrap=True)
        table.add_column("n", justify="right")
        table.add_column("tags")
        table.add_column("reporters")
        for rec in records:
            table.add_row(
                style_type(str(rec.get("type") or "?")),
                display_value(str(rec.get("value") or ""), rec.get("type"), args.defang),
                str(rec.get("first_seen") or "—"),
                str(rec.get("last_seen") or "—"),
                str(rec.get("count") or ""),
                style_tags(rec.get("tags") or []),
                " ".join("@" + str(u).lstrip("@") for u in (rec.get("users") or [])),
            )
        console.print(table)
        if args.tweets:
            for rec in records:
                for tw in rec.get("tweets") or []:
                    console.print(f"  {tw}")

    reg = data.get("reg") or {}
    if reg:
        bits = [
            f"apex={reg.get('apex') or '—'}",
            f"registrar={reg.get('registrar') or '—'}",
            f"created={reg.get('created') or '—'}",
            f"asn={reg.get('asn') or '—'}",
            f"org={reg.get('org') or '—'}",
            f"newly_registered={reg.get('newly_registered')}",
        ]
        if reg.get("ips"):
            bits.append("ips=" + ", ".join(str(i) for i in reg["ips"][:6]))
        console.print(Panel("\n".join(bits), title="registration / network", border_style="blue"))

    campaigns = data.get("campaigns") or []
    if campaigns:
        console.print("[head]related campaigns[/head]")
        for c in campaigns:
            console.print(
                f"  [accent]{c.get('id')}[/accent]  {c.get('name')}  "
                f"[muted]{c.get('confidence')} · {c.get('ioc_count')} iocs[/muted]"
            )

    archive = data.get("archive") or {}
    if archive.get("total"):
        console.print(
            f"[muted]archive (pre-365d): {archive.get('total')} extra record(s)[/muted]"
        )
    return 0


def cmd_campaigns(args: argparse.Namespace) -> int:
    if args.id:
        path = f"/v1/campaigns/{args.id}"
        data, _resp = api_get(path)
        if args.json:
            print(json.dumps(data, indent=2))
            return 0
        header = data.get("campaign") or data
        # some responses wrap, some are the campaign object itself
        if "campaigns" in data and not args.id.startswith("tfc-"):
            header = data
        _print_campaign(header if isinstance(header, dict) else data, args)
        iocs = data.get("iocs") or data.get("records") or []
        if iocs and isinstance(iocs, list) and isinstance(iocs[0], dict) and "value" in iocs[0]:
            console.print(ioc_table(iocs, defang=args.defang, limit=args.limit))
            summarize(iocs)
        return 0

    data, _resp = api_get("/v1/campaigns")
    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    campaigns = data.get("campaigns") or []
    console.print(
        Panel(
            f"[head]{data.get('campaign_count', len(campaigns))} campaigns[/head]  "
            f"window={data.get('window')}  generated={data.get('generated_at')}",
            border_style="magenta",
        )
    )
    table = Table(box=box.SIMPLE_HEAVY, header_style="head", expand=True)
    table.add_column("id", style="accent", no_wrap=True)
    table.add_column("name", overflow="fold", min_width=28)
    table.add_column("conf", no_wrap=True)
    table.add_column("iocs", justify="right")
    table.add_column("7d", justify="right")
    table.add_column("last seen", no_wrap=True)
    table.add_column("target")
    shown = campaigns[: args.limit] if args.limit else campaigns
    for c in shown:
        conf = str(c.get("confidence") or "")
        conf_style = {"high": "ok", "medium": "warn", "low": "muted"}.get(conf, "white")
        target = c.get("targeted_brand") or c.get("targeted_sector") or "—"
        table.add_row(
            str(c.get("id") or ""),
            str(c.get("name") or ""),
            Text(conf, style=conf_style),
            str(c.get("ioc_count") or ""),
            str(c.get("ioc_count_7d") if c.get("ioc_count_7d") is not None else "—"),
            str(c.get("last_seen") or ""),
            str(target),
        )
    console.print(table)
    console.print("[muted]inspect one with:[/muted] iocaw campaigns --id tfc-xxxxxxxxxxxx")
    return 0


def _print_campaign(c: dict[str, Any], args: argparse.Namespace) -> None:
    console.print(
        Panel(
            f"[head]{c.get('name', c.get('id', 'campaign'))}[/head]\n"
            f"[muted]{c.get('id', '')}[/muted]\n\n"
            f"{c.get('context') or ''}",
            border_style="magenta",
        )
    )
    meta = [
        f"confidence={c.get('confidence')}",
        f"iocs={c.get('ioc_count')}",
        f"first={c.get('first_seen')}",
        f"last={c.get('last_seen')}",
        f"brand={c.get('targeted_brand') or '—'}",
        f"sector={c.get('targeted_sector') or '—'}",
    ]
    if c.get("ttps"):
        meta.append("ttps=" + ", ".join(str(t) for t in c["ttps"]))
    console.print(" · ".join(meta))


def cmd_trends(args: argparse.Namespace) -> int:
    data, _resp = api_get("/v1/trends")
    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    console.print(
        Panel(
            f"[head]trends[/head]  generated={data.get('generated_at')}",
            border_style="cyan",
        )
    )

    movers = data.get("movers") or {}
    # movers may be {tag: {...}} or {items: [...]} or {up:[], down:[]}
    mover_rows = _normalize_movers(movers)
    if mover_rows:
        table = Table(title="week-over-week tag movers", box=box.SIMPLE_HEAVY, header_style="head")
        table.add_column("tag")
        table.add_column("now", justify="right")
        table.add_column("prev", justify="right")
        table.add_column("Δ", justify="right")
        table.add_column("%", justify="right")
        for m in mover_rows[: args.limit or 15]:
            delta = m.get("delta")
            pct = m.get("pct")
            dstyle = "ok" if (delta or 0) > 0 else "err" if (delta or 0) < 0 else "muted"
            table.add_row(
                style_tag(str(m.get("tag") or "")),
                str(m.get("count", m.get("current", m.get("now", "")))),
                str(m.get("previous", m.get("prev", ""))),
                Text(str(delta), style=dstyle),
                Text("" if pct is None else f"{pct:.0f}%", style=dstyle),
            )
        console.print(table)

    tlds = data.get("tlds") or {}
    tld_rows = _normalize_counts_map(tlds)
    if tld_rows:
        table = Table(title="hot TLDs (30d)", box=box.SIMPLE_HEAVY, header_style="head")
        table.add_column("tld", style="bright_cyan")
        table.add_column("count", justify="right")
        for name, n in tld_rows[: args.limit or 12]:
            table.add_row(name, str(n))
        console.print(table)

    novelty = data.get("novelty") or {}
    if novelty:
        console.print("[head]novelty (this week)[/head]  " + _fmt_dict(novelty))

    daily = data.get("daily") or {}
    totals = daily.get("total") if isinstance(daily, dict) else None
    if isinstance(totals, list) and totals:
        last = totals[-7:]
        spark = _spark(last)
        console.print(f"[head]last 7 daily totals[/head]  {spark}  {last}")
    return 0


def _normalize_movers(movers: Any) -> list[dict[str, Any]]:
    if isinstance(movers, list):
        return [m for m in movers if isinstance(m, dict)]
    if not isinstance(movers, dict):
        return []
    for key in ("items", "tags", "top", "up"):
        if isinstance(movers.get(key), list):
            rows = [m for m in movers[key] if isinstance(m, dict)]
            down = movers.get("down")
            if key == "up" and isinstance(down, list):
                rows = rows + [m for m in down if isinstance(m, dict)]
            return rows
    rows = []
    for tag, payload in movers.items():
        if tag in {"generated_at", "window", "version"}:
            continue
        if isinstance(payload, dict):
            rows.append({"tag": tag, **payload})
        elif isinstance(payload, (int, float)):
            rows.append({"tag": tag, "current": payload})
    rows.sort(key=lambda m: abs(m.get("delta") or m.get("current") or 0), reverse=True)
    return rows


def _normalize_counts_map(obj: Any) -> list[tuple[str, int]]:
    if isinstance(obj, list):
        out = []
        for item in obj:
            if isinstance(item, dict):
                name = item.get("tld") or item.get("name") or item.get("tag") or "?"
                n = item.get("count") or item.get("total") or 0
                out.append((str(name), int(n)))
        return out
    if isinstance(obj, dict):
        if all(isinstance(v, (int, float)) for v in obj.values()):
            return sorted(obj.items(), key=lambda kv: kv[1], reverse=True)
        for key in ("items", "top", "tlds"):
            if key in obj:
                return _normalize_counts_map(obj[key])
    return []


def _fmt_dict(d: dict[str, Any]) -> str:
    skip = {"generated_at", "version", "window"}
    parts = []
    for k, v in d.items():
        if k in skip or isinstance(v, (dict, list)):
            continue
        parts.append(f"{k}={v}")
    return "  ".join(parts)


def _spark(nums: list[int]) -> str:
    if not nums:
        return ""
    blocks = "▁▂▃▄▅▆▇█"
    lo, hi = min(nums), max(nums)
    if hi == lo:
        return blocks[0] * len(nums)
    out = []
    for n in nums:
        idx = int((n - lo) / (hi - lo) * (len(blocks) - 1))
        out.append(blocks[idx])
    return "".join(out)


def cmd_counts(args: argparse.Namespace) -> int:
    data, _resp = api_get("/v1/counts")
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    windows = data.get("windows") or {}
    want = [args.window] if args.window else list(WINDOWS)
    console.print(
        Panel(
            f"[head]counts[/head]  generated={data.get('generated_at')}",
            border_style="cyan",
        )
    )
    for w in want:
        bucket = windows.get(w)
        if not bucket:
            continue
        types = bucket.get("types") or {}
        tags = bucket.get("tags") or {}
        type_bits = "  ".join(f"{k}={v}" for k, v in types.items())
        console.print(
            f"\n[accent]{w}[/accent]  [ok]{bucket.get('total', 0)}[/ok]  "
            f"[muted]{bucket.get('first_date')} → {bucket.get('last_date')}[/muted]"
        )
        console.print(f"  types  {type_bits}")
        top_tags = sorted(tags.items(), key=lambda kv: kv[1], reverse=True)[: args.limit or 12]
        table = Table(box=box.MINIMAL, show_header=False, pad_edge=False)
        table.add_column("tag")
        table.add_column("n", justify="right", style="ok")
        for tag, n in top_tags:
            table.add_row(style_tag(tag), str(n))
        console.print(table)
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    data, resp = api_get("/v1/status")
    if _args.json:
        print(json.dumps(data, indent=2))
        return 0
    stale = data.get("stale") or data.get("any_stale")
    border = "yellow" if stale else "green"
    console.print(
        Panel(
            f"[head]feed status[/head]  stale={stale}  age={data.get('age_seconds')}s  "
            f"checked={data.get('checked_at')}",
            border_style=border,
        )
    )
    contract = data.get("contract") or {}
    if contract:
        console.print(
            f"[muted]license={contract.get('license')}  tlp={contract.get('tlp')}  "
            f"docs={contract.get('docs')}[/muted]"
        )
    arts = data.get("artifacts") or {}
    table = Table(box=box.SIMPLE_HEAVY, header_style="head")
    table.add_column("artifact")
    table.add_column("window")
    table.add_column("rows", justify="right")
    table.add_column("updated")
    table.add_column("age", justify="right")
    table.add_column("stale")
    interesting = [
        "today.csv",
        "week.csv",
        "month.csv",
        "year.csv",
        "campaigns.json",
        "counts.json",
        "trends.json",
    ]
    names = [n for n in interesting if n in arts] + [
        n for n in arts if n not in interesting
    ]
    for name in names[:20]:
        a = arts[name]
        if not isinstance(a, dict):
            continue
        flag = Text("yes", style="warn") if a.get("stale") else Text("no", style="ok")
        table.add_row(
            name,
            str(a.get("window") or "—"),
            str(a.get("rows") or "—"),
            str(a.get("updated_at") or "—"),
            str(a.get("age_seconds") if a.get("age_seconds") is not None else "—"),
            flag,
        )
    console.print(table)
    console.print(f"[muted]cache headers: {meta_line(resp)}[/muted]")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    since = args.since or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    user = args.user
    if user and not user.startswith("@") and user not in IOC_TYPES:
        user = "@" + user
    filters = [f for f in (args.tag, user, args.type) if f]
    console.print(
        f"[caw]watching[/caw] since [accent]{since}[/accent]  "
        f"every {args.interval}s  ctrl-c to stop"
    )
    seen: set[tuple[str, str, str]] = set()
    try:
        while True:
            path = "/v1/since/" + quote(since, safe=":-")
            if filters:
                path += "/" + "/".join(filters)
            try:
                data, resp = api_get(path)
            except TweetFeedError as exc:
                console.print(f"[err]{exc}[/err]")
                time.sleep(args.interval)
                continue
            rows = data if isinstance(data, list) else []
            fresh = []
            for r in rows:
                key = (str(r.get("date")), str(r.get("type")), str(r.get("value")))
                if key in seen:
                    continue
                seen.add(key)
                fresh.append(r)
            if fresh:
                console.print(
                    f"\n[ok]+{len(fresh)}[/ok]  {datetime.now().strftime('%H:%M:%S')}  "
                    f"{meta_line(resp)}"
                )
                console.print(ioc_table(fresh, defang=args.defang, limit=None))
                last_date = max(str(r.get("date") or "") for r in fresh)
                # feed dates look like "2026-09-11 13:01:31"
                if last_date:
                    since = last_date.replace(" ", "T") + "Z"
            else:
                console.print(
                    f"[muted]{datetime.now().strftime('%H:%M:%S')}  silence ({len(rows)} already seen)[/muted]"
                )
            time.sleep(args.interval)
    except KeyboardInterrupt:
        console.print("\n[caw]caw.[/caw] stopped.")
    return 0


def cmd_blocklist(args: argparse.Namespace) -> int:
    kind = args.kind
    # TweetFeed serves these under /v1/blocklist/
    path = f"/v1/blocklist/{kind}.txt"
    text, resp = api_get(path, expect_json=False)
    lines = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    console.print(
        Panel(
            f"[head]blocklist {kind}[/head]  {len(lines)} entries",
            subtitle=str(meta_line(resp)),
            border_style="cyan",
        )
    )
    shown = lines[: args.limit] if args.limit else lines
    for ln in shown:
        console.print(defang_value(ln) if args.defang else ln)
    if args.limit and len(lines) > args.limit:
        console.print(f"[muted]showing {args.limit} of {len(lines)}[/muted]")
    if args.export:
        with open(args.export, "w", encoding="utf-8") as fh:
            fh.write(text)
        console.print(f"[ok]wrote[/ok] {args.export}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="raw JSON to stdout")
    p.add_argument("--defang", action="store_true", help="hxxp / [.] the values")
    p.add_argument("--limit", type=int, default=40, help="max rows to print (default 40, 0 = all)")
    p.add_argument("--export", metavar="FILE", help="write csv / json / txt")


def add_filters(p: argparse.ArgumentParser) -> None:
    p.add_argument("--type", choices=IOC_TYPES, help="url / domain / ip / sha256 / md5")
    p.add_argument("--tag", help="family or category, e.g. phishing, lumma, CobaltStrike")
    p.add_argument("--user", help="reporter handle, with or without @")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="iocaw",
        description="IOCaw — colorful hunter for the TweetFeed.live IOC API (CC0, no auth).",
        epilog="Data is community-sourced and unverified. Do not visit live malicious URLs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"{NAME} {VERSION}")
    p.add_argument("--quiet", action="store_true", help="skip the banner")

    sub = p.add_subparsers(dest="cmd", required=True)

    feed = sub.add_parser("feed", help="pull IOCs for a time window")
    feed.add_argument("window", nargs="?", default="today", choices=WINDOWS)
    add_filters(feed)
    add_common(feed)
    feed.add_argument("--contains", help="client-side substring filter")
    feed.add_argument("--values-only", action="store_true", help="print just IOC values")
    feed.add_argument("--tweets", action="store_true", help="also print source tweet URLs")
    feed.set_defaults(func=cmd_feed)

    look = sub.add_parser("lookup", help="exact-match one IOC across 365 days")
    look.add_argument("value", help="url, domain, ip, or hash")
    look.add_argument("--json", action="store_true")
    look.add_argument("--defang", action="store_true")
    look.add_argument("--tweets", action="store_true")
    look.set_defaults(func=cmd_lookup)

    camp = sub.add_parser("campaigns", help="AI-clustered campaigns")
    camp.add_argument("--id", help="campaign id like tfc-8fe36f50a145")
    add_common(camp)
    camp.set_defaults(func=cmd_campaigns)

    tr = sub.add_parser("trends", help="movers, TLDs, novelty")
    tr.add_argument("--json", action="store_true")
    tr.add_argument("--limit", type=int, default=15)
    tr.set_defaults(func=cmd_trends)

    co = sub.add_parser("counts", help="totals by window / type / tag")
    co.add_argument("window", nargs="?", choices=WINDOWS)
    co.add_argument("--json", action="store_true")
    co.add_argument("--limit", type=int, default=12)
    co.set_defaults(func=cmd_counts)

    st = sub.add_parser("status", help="pipeline freshness")
    st.add_argument("--json", action="store_true")
    st.set_defaults(func=cmd_status)

    wh = sub.add_parser("watch", help="poll /v1/since for new IOCs")
    wh.add_argument("--since", help="ISO8601 UTC, default now")
    wh.add_argument("--interval", type=int, default=60, help="seconds between polls")
    add_filters(wh)
    wh.add_argument("--defang", action="store_true")
    wh.set_defaults(func=cmd_watch)

    bl = sub.add_parser("blocklist", help="ready-made 30-day blocklists")
    bl.add_argument(
        "kind",
        choices=[
            "domains",
            "ips",
            "urls",
            "sha256",
            "md5",
            "hosts",
            "adguard",
            "rpz",
            "dnsmasq",
            "nrd-domains",
        ],
    )
    bl.add_argument("--limit", type=int, default=30)
    bl.add_argument("--defang", action="store_true")
    bl.add_argument("--export", metavar="FILE")
    bl.set_defaults(func=cmd_blocklist)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.quiet and not getattr(args, "json", False):
        print_banner()
        console.print(
            f"[muted]{NAME} {VERSION}  ·  {DOCS}  ·  no auth, be polite[/muted]\n"
        )
    try:
        return int(args.func(args) or 0)
    except TweetFeedError as exc:
        console.print(f"[err]{exc}[/err]")
        return 2
    except KeyboardInterrupt:
        console.print("\n[caw]caw.[/caw]")
        return 130


if __name__ == "__main__":
    sys.exit(main())
