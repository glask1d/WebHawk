#!/usr/bin/env python3
"""urlscan.io API client.

A colorful command-line client for searching historical scans, submitting new
scans, polling results, downloading screenshots/DOM snapshots, and checking
quotas.

Authentication
--------------
Provide an API key via, in order of precedence:
  1. --api-key
  2. URLSCAN_API_KEY environment variable
  3. ~/.config/urlscan/api_key  (first line of the file)

As of May 2026 result and DOM endpoints require a key. Search and quotas still
work anonymously with a smaller per-IP budget, but a key is recommended.

Examples
--------
  %(prog)s search 'page.domain:example.com AND date:>now-7d'
  %(prog)s search domain:paypal.com --size 25 --json
  %(prog)s scan https://example.com --visibility unlisted --wait
  %(prog)s result 0196d976-07f6-7aae-8a57-aa019145f31c
  %(prog)s screenshot <uuid> -o shot.png
  %(prog)s quotas
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

BASE = "https://urlscan.io"
USER_AGENT = "urlscan-cli/1.0 (+https://urlscan.io; python3)"
CONFIG_PATHS = (
    Path.home() / ".config" / "urlscan" / "api_key",
    Path.home() / ".urlscan_api_key",
)


# ---------------------------------------------------------------------------
# Color
# ---------------------------------------------------------------------------

class Palette:
    """ANSI palette that no-ops when stdout is not a TTY or --no-color is set."""

    def __init__(self, enabled: bool) -> None:
        def wrap(code: str) -> str:
            return code if enabled else ""

        self.reset = wrap("\033[0m")
        self.bold = wrap("\033[1m")
        self.dim = wrap("\033[2m")
        self.italic = wrap("\033[3m")
        self.underline = wrap("\033[4m")

        self.black = wrap("\033[30m")
        self.red = wrap("\033[31m")
        self.green = wrap("\033[32m")
        self.yellow = wrap("\033[33m")
        self.blue = wrap("\033[34m")
        self.magenta = wrap("\033[35m")
        self.cyan = wrap("\033[36m")
        self.white = wrap("\033[37m")

        self.bright_red = wrap("\033[91m")
        self.bright_green = wrap("\033[92m")
        self.bright_yellow = wrap("\033[93m")
        self.bright_blue = wrap("\033[94m")
        self.bright_magenta = wrap("\033[95m")
        self.bright_cyan = wrap("\033[96m")
        self.bright_white = wrap("\033[97m")

        self.bg_red = wrap("\033[41m")
        self.bg_green = wrap("\033[42m")
        self.bg_yellow = wrap("\033[43m")

    def paint(self, text: Any, *styles: str) -> str:
        body = "" if text is None else str(text)
        return f"{''.join(styles)}{body}{self.reset}"


C = Palette(enabled=False)  # replaced in main()


def _want_color(no_color_flag: bool) -> bool:
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class APIError(Exception):
    def __init__(
        self,
        status: int,
        message: str,
        body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.body = body
        self.headers = headers or {}


class RateLimitInfo:
    def __init__(self, headers: dict[str, str]) -> None:
        h = {k.lower(): v for k, v in headers.items()}
        self.scope = h.get("x-rate-limit-scope")
        self.action = h.get("x-rate-limit-action")
        self.window = h.get("x-rate-limit-window")
        self.limit = _maybe_int(h.get("x-rate-limit-limit"))
        self.remaining = _maybe_int(h.get("x-rate-limit-remaining"))
        self.reset = h.get("x-rate-limit-reset")
        self.reset_after = _maybe_int(h.get("x-rate-limit-reset-after"))

    @property
    def present(self) -> bool:
        return self.action is not None or self.remaining is not None

    def summary(self) -> str:
        if not self.present:
            return ""
        parts = []
        if self.action:
            parts.append(self.action)
        if self.window:
            parts.append(self.window)
        quota = ""
        if self.remaining is not None and self.limit is not None:
            quota = f"{self.remaining}/{self.limit} left"
        elif self.remaining is not None:
            quota = f"{self.remaining} left"
        bits = " ".join(p for p in parts if p)
        extra = f" · resets in {self.reset_after}s" if self.reset_after is not None else ""
        return f"{bits} {quota}{extra}".strip()


def _maybe_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


class Client:
    def __init__(self, api_key: str | None, timeout: float = 30.0) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.last_rate: RateLimitInfo | None = None

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
        raw: bool = False,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, Any, dict[str, str]]:
        url = path if path.startswith("http") else f"{BASE}{path}"
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += ("&" if "?" in url else "?") + urllib.parse.urlencode(clean)

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, */*",
        }
        if self.api_key:
            headers["API-Key"] = self.api_key
        data: bytes | None = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.getcode()
                resp_headers = {k: v for k, v in resp.headers.items()}
                body_bytes = resp.read()
        except urllib.error.HTTPError as exc:
            resp_headers = {k: v for k, v in exc.headers.items()} if exc.headers else {}
            body_bytes = exc.read() if exc.fp else b""
            self.last_rate = RateLimitInfo(resp_headers)
            parsed = _try_json(body_bytes)
            message = _extract_message(parsed, body_bytes, default=exc.reason)
            raise APIError(exc.code, message, parsed, resp_headers) from None
        except urllib.error.URLError as exc:
            raise APIError(0, f"network error: {exc.reason}") from None

        self.last_rate = RateLimitInfo(resp_headers)
        if raw:
            return status, body_bytes, resp_headers
        return status, _try_json(body_bytes), resp_headers

    def search(
        self,
        query: str,
        size: int = 20,
        search_after: str | None = None,
        datasource: str | None = None,
    ) -> dict[str, Any]:
        _, body, _ = self.request(
            "GET",
            "/api/v1/search/",
            params={
                "q": query,
                "size": size,
                "search_after": search_after,
                "datasource": datasource,
            },
        )
        return body if isinstance(body, dict) else {"raw": body}

    def submit(
        self,
        url: str,
        visibility: str | None = None,
        country: str | None = None,
        tags: list[str] | None = None,
        customagent: str | None = None,
        referer: str | None = None,
        override_safety: bool = False,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"url": url}
        if visibility:
            payload["visibility"] = visibility
        if country:
            payload["country"] = country
        if tags:
            payload["tags"] = tags
        if customagent:
            payload["customagent"] = customagent
        if referer:
            payload["referer"] = referer
        if override_safety:
            payload["overrideSafety"] = "true"
        _, body, _ = self.request("POST", "/api/v1/scan/", payload=payload)
        return body if isinstance(body, dict) else {"raw": body}

    def result(self, uuid: str) -> dict[str, Any]:
        _, body, _ = self.request("GET", f"/api/v1/result/{uuid}/")
        return body if isinstance(body, dict) else {"raw": body}

    def wait_for_result(
        self,
        uuid: str,
        timeout: float = 120.0,
        initial_delay: float = 10.0,
        interval: float = 3.0,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        remaining = initial_delay
        first = True
        while True:
            if remaining > 0:
                _spinner_sleep(remaining, "waiting for scan" if first else "polling")
                first = False
            try:
                return self.result(uuid)
            except APIError as exc:
                if exc.status == 404:
                    now = time.monotonic()
                    if now >= deadline:
                        raise APIError(
                            404,
                            f"scan {uuid} did not finish within {timeout:.0f}s",
                        ) from None
                    remaining = min(interval, max(0.0, deadline - now))
                    continue
                raise

    def quotas(self) -> dict[str, Any]:
        last_err: APIError | None = None
        for path in ("/api/v1/quotas", "/user/quotas/"):
            try:
                _, body, _ = self.request("GET", path)
                return body if isinstance(body, dict) else {"raw": body}
            except APIError as exc:
                last_err = exc
                if exc.status in (404, 405):
                    continue
                raise
        if last_err:
            raise last_err
        return {}

    def whoami(self) -> dict[str, Any]:
        _, body, _ = self.request("GET", "/user/username")
        return body if isinstance(body, dict) else {"raw": body}

    def download(self, url: str) -> bytes:
        _, body, _ = self.request("GET", url, raw=True)
        if not isinstance(body, (bytes, bytearray)):
            raise APIError(0, "expected binary response")
        return bytes(body)


def _try_json(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        try:
            return body.decode("utf-8", errors="replace")
        except Exception:
            return body


def _extract_message(parsed: Any, raw: bytes, default: str) -> str:
    if isinstance(parsed, dict):
        for key in ("message", "description", "error", "detail", "warning"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                extra = parsed.get("description") if key == "message" else None
                if extra and extra != value:
                    return f"{value} — {extra}"
                return value
    if isinstance(parsed, str) and parsed.strip():
        return parsed.strip()[:400]
    if raw:
        return raw.decode("utf-8", errors="replace")[:400]
    return default


def _spinner_sleep(seconds: float, label: str) -> None:
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    end = time.monotonic() + seconds
    i = 0
    interactive = sys.stderr.isatty()
    while True:
        left = end - time.monotonic()
        if left <= 0:
            break
        if interactive:
            frame = frames[i % len(frames)]
            sys.stderr.write(
                f"\r{C.cyan}{frame}{C.reset} {C.dim}{label}{C.reset} "
                f"{C.yellow}{left:4.1f}s{C.reset}   "
            )
            sys.stderr.flush()
        i += 1
        time.sleep(0.08)
    if interactive:
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def load_api_key(cli_value: str | None) -> str | None:
    if cli_value:
        return cli_value.strip()
    env = os.environ.get("URLSCAN_API_KEY")
    if env:
        return env.strip()
    for path in CONFIG_PATHS:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if text:
            return text.splitlines()[0].strip()
    return None


# ---------------------------------------------------------------------------
# Pretty printers
# ---------------------------------------------------------------------------

def emit_json(data: Any) -> None:
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False, default=str)
    sys.stdout.write("\n")


def print_rate(client: Client) -> None:
    if client.last_rate and client.last_rate.present:
        print(C.paint(f"  quota  {client.last_rate.summary()}", C.dim))


def print_kv(label: str, value: Any, color: str | None = None) -> None:
    if value is None or value == "" or value == []:
        return
    painted = C.paint(value, color) if color else str(value)
    print(f"  {C.dim}{label:<14}{C.reset} {painted}")


def verdict_badge(verdicts: dict[str, Any] | None) -> str:
    if not verdicts:
        return C.paint("unknown", C.dim)
    overall = verdicts.get("overall") or {}
    malicious = bool(overall.get("malicious"))
    score = overall.get("score")
    engines = verdicts.get("engines") or {}
    community = verdicts.get("community") or {}
    if malicious or engines.get("malicious") or community.get("malicious"):
        extra = f" score={score}" if score is not None else ""
        return C.paint(f"MALICIOUS{extra}", C.bold, C.bright_red)
    if score not in (None, 0):
        return C.paint(f"score={score}", C.yellow)
    return C.paint("clean", C.bright_green)


def visibility_badge(value: str | None) -> str:
    if not value:
        return C.paint("-", C.dim)
    palette = {
        "public": C.bright_cyan,
        "unlisted": C.bright_yellow,
        "private": C.bright_magenta,
    }
    return C.paint(value, palette.get(value, C.white))


def print_search(data: dict[str, Any], query: str) -> None:
    results = data.get("results") or []
    total = data.get("total")
    took = data.get("took")
    has_more = data.get("has_more")

    header = C.paint("urlscan search", C.bold, C.bright_cyan)
    meta_bits = [C.paint(query, C.italic, C.white)]
    if total is not None:
        shown = f"showing {len(results)} of {total}"
        if has_more:
            shown += "+ (has_more)"
        meta_bits.append(C.paint(shown, C.dim))
    if took is not None:
        meta_bits.append(C.paint(f"{took}ms", C.dim))
    print(f"{header}  {' · '.join(meta_bits)}")
    print()

    if not results:
        print(C.paint("  no results", C.yellow))
        return

    last_sort = None
    for i, hit in enumerate(results, 1):
        page = hit.get("page") or {}
        task = hit.get("task") or {}
        stats = hit.get("stats") or {}
        uuid = hit.get("_id") or task.get("uuid") or ""
        url = page.get("url") or task.get("url") or "-"
        title = (page.get("title") or "").strip()
        ip = page.get("ip") or "-"
        country = page.get("country") or ""
        server = page.get("server") or ""
        asn = page.get("asn") or ""
        asnname = page.get("asnname") or ""
        when = task.get("time") or hit.get("indexedAt") or ""
        vis = task.get("visibility")
        malicious = bool((hit.get("verdicts") or {}).get("malicious"))

        idx = C.paint(f"{i:>3}.", C.dim)
        flag = C.paint(" ✖", C.bold, C.bright_red) if malicious else ""
        print(f"{idx} {C.paint(url, C.bold, C.bright_white)}{flag}")
        if title:
            print(f"     {C.paint(title, C.cyan)}")
        details = [
            C.paint(when, C.dim) if when else "",
            visibility_badge(vis),
            C.paint(f"{ip} {country}".strip(), C.yellow) if ip != "-" else "",
            C.paint(f"{asn} {asnname}".strip(), C.magenta) if asn else "",
            C.paint(server, C.dim) if server else "",
        ]
        line = "  ·  ".join(part for part in details if part)
        if line:
            print(f"     {line}")
        extra = []
        if stats.get("requests") is not None:
            extra.append(f"req {stats['requests']}")
        if stats.get("uniqIPs") is not None:
            extra.append(f"ips {stats['uniqIPs']}")
        if stats.get("dataLength") is not None:
            extra.append(f"bytes {stats['dataLength']}")
        if extra:
            print(f"     {C.paint('  '.join(extra), C.dim)}")
        if uuid:
            print(f"     {C.paint(uuid, C.blue)}  {C.paint(f'{BASE}/result/{uuid}/', C.dim)}")
        print()
        last_sort = hit.get("sort")

    if last_sort:
        token = ",".join(str(x) for x in last_sort) if isinstance(last_sort, list) else str(last_sort)
        print(C.paint(f"  next page:  --after '{token}'", C.dim))


def print_submission(data: dict[str, Any]) -> None:
    print(C.paint("scan submitted", C.bold, C.bright_green))
    print_kv("uuid", data.get("uuid"), C.bright_white)
    print_kv("url", data.get("url"), C.cyan)
    print_kv("visibility", data.get("visibility"), C.yellow)
    print_kv("country", data.get("country"))
    print_kv("message", data.get("message"), C.dim)
    print_kv("result", data.get("result"), C.blue)
    print_kv("api", data.get("api"), C.blue)


def print_result_summary(data: dict[str, Any]) -> None:
    task = data.get("task") or {}
    page = data.get("page") or {}
    stats = data.get("stats") or {}
    lists = data.get("lists") or {}
    verdicts = data.get("verdicts") or {}
    uuid = task.get("uuid") or data.get("task", {}).get("uuid")

    print(C.paint("scan result", C.bold, C.bright_cyan))
    print_kv("uuid", uuid, C.bright_white)
    print_kv("tasked", task.get("url"), C.cyan)
    print_kv("final url", page.get("url"), C.cyan)
    print_kv("title", page.get("title"))
    print_kv("time", task.get("time"), C.dim)
    print_kv("visibility", task.get("visibility"), C.yellow)
    print_kv("method", task.get("method"))
    print_kv("country", f"{page.get('country', '')} {page.get('city', '')}".strip())
    print_kv("ip", page.get("ip"), C.yellow)
    asn = " ".join(
        str(x)
        for x in (page.get("asn"), page.get("asnname"))
        if x
    )
    print_kv("asn", asn, C.magenta)
    print_kv("server", page.get("server"))
    print_kv("tls", page.get("tlsIssuer") or page.get("tlsValidDays"))
    print_kv("status", page.get("status"))
    print()
    print(f"  {C.dim}{'verdict':<14}{C.reset} {verdict_badge(verdicts)}")
    overall = verdicts.get("overall") or {}
    cats = overall.get("categories") or verdicts.get("urlscan", {}).get("categories")
    if cats:
        print_kv("categories", ", ".join(str(c) for c in cats), C.red)
    brands = overall.get("brands") or verdicts.get("urlscan", {}).get("brands")
    if brands:
        print_kv("brands", ", ".join(str(b) for b in brands), C.yellow)

    print()
    print(C.paint("  stats", C.bold))
    print_kv("requests", stats.get("requests"))
    print_kv("uniq IPs", stats.get("uniqIPs"))
    print_kv("countries", stats.get("uniqCountries"))
    print_kv("dataLength", stats.get("dataLength"))
    print_kv("encoded", stats.get("encodedDataLength"))

    def preview(label: str, items: Any, limit: int = 8) -> None:
        if not items:
            return
        values = [str(x) for x in items]
        shown = values[:limit]
        suffix = f"  (+{len(values) - limit} more)" if len(values) > limit else ""
        print_kv(label, ", ".join(shown) + suffix)

    print()
    print(C.paint("  indicators", C.bold))
    preview("domains", lists.get("domains") or lists.get("linkDomains"))
    preview("ips", lists.get("ips"))
    preview("asns", lists.get("asns"))
    preview("hashes", lists.get("hashes"))
    preview("urls", lists.get("urls"), limit=5)
    preview("certificates", lists.get("certificates"), limit=4)

    if uuid:
        print()
        print_kv("report", f"{BASE}/result/{uuid}/", C.blue)
        print_kv("screenshot", f"{BASE}/screenshots/{uuid}.png", C.blue)
        print_kv("dom", f"{BASE}/dom/{uuid}/", C.blue)


def print_quotas(data: dict[str, Any]) -> None:
    print(C.paint("urlscan quotas", C.bold, C.bright_cyan))
    scope = data.get("scope")
    if scope:
        print_kv("scope", scope, C.yellow)
    limits = data.get("limits") or data
    if not isinstance(limits, dict):
        emit_json(data)
        return

    skip = {"features", "queryVisibility", "queryableFields"}
    actions = [
        (k, v)
        for k, v in limits.items()
        if k not in skip and isinstance(v, dict)
    ]
    if not actions and "search" not in limits:
        # /user/quotas sometimes wraps differently
        maybe = data.get("data") or data.get("quotas")
        if isinstance(maybe, dict):
            actions = [
                (k, v) for k, v in maybe.items() if isinstance(v, dict)
            ]

    print()
    header = (
        f"  {C.bold}{'action':<16}{'window':<10}{'used':>8}{'remain':>10}"
        f"{'limit':>8}{'pct':>7}{C.reset}"
    )
    print(header)
    print(C.paint("  " + "─" * 59, C.dim))

    order = ("minute", "hour", "day")
    for action, windows in actions:
        printed = False
        for window in order:
            bucket = windows.get(window)
            if not isinstance(bucket, dict):
                continue
            used = bucket.get("used", 0)
            remaining = bucket.get("remaining", 0)
            limit = bucket.get("limit", 0)
            pct = bucket.get("percent")
            if pct is None and limit:
                pct = int(round((used / limit) * 100)) if limit else 0
            if remaining == 0 and limit:
                color = C.bright_red
            elif isinstance(pct, (int, float)) and pct >= 80:
                color = C.yellow
            else:
                color = C.bright_green
            print(
                f"  {C.cyan}{action:<16}{C.reset}{window:<10}"
                f"{used:>8}{C.paint(f'{remaining:>10}', color)}{limit:>8}"
                f"{str(pct) + '%':>7}"
            )
            printed = True
        if printed:
            print()

    vis = data.get("queryVisibility") or limits.get("queryVisibility")
    if vis:
        print_kv("visibility", ", ".join(vis) if isinstance(vis, list) else vis)
    features = data.get("features") or limits.get("features")
    if features:
        print_kv("features", ", ".join(str(x) for x in features))


def print_whoami(data: dict[str, Any]) -> None:
    print(C.paint("urlscan identity", C.bold, C.bright_cyan))
    if not isinstance(data, dict):
        print(f"  {data}")
        return
    for key in (
        "username",
        "email",
        "name",
        "role",
        "plan",
        "subscription",
        "team",
        "uuid",
    ):
        print_kv(key, data.get(key))
    leftover = {
        k: v
        for k, v in data.items()
        if k
        not in {
            "username",
            "email",
            "name",
            "role",
            "plan",
            "subscription",
            "team",
            "uuid",
        }
        and not isinstance(v, (dict, list))
    }
    for key, value in leftover.items():
        print_kv(key, value)


def die(message: str, code: int = 1) -> None:
    print(C.paint(f"error: {message}", C.bold, C.bright_red), file=sys.stderr)
    raise SystemExit(code)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _looks_like_url(text: str) -> bool:
    lowered = text.strip().lower()
    if lowered.startswith(("http://", "https://")):
        return True
    # bare host with a path, e.g. example.com/login — not valid ES syntax
    if "://" not in text and "/" in text and " " not in text and ":" not in text:
        host = text.split("/", 1)[0]
        return "." in host and not host.startswith(".")
    return False


def normalize_search_query(raw: str) -> tuple[str, str | None]:
    """Turn a pasted URL into a valid Elasticsearch query string.

    urlscan's search endpoint uses ES query-string syntax. Characters like
    ``/`` and ``:`` are reserved, so ``search https://evil.tld`` 400s unless
    we rewrite it.
    """
    text = raw.strip()
    if not _looks_like_url(text):
        return text, None

    if not text.lower().startswith(("http://", "https://")):
        text = "https://" + text

    parsed = urllib.parse.urlparse(text)
    host = (parsed.hostname or "").lower().rstrip(".")
    # Rebuild a stable URL for exact-match clauses (drop fragment).
    path = parsed.path or ""
    if path == "/":
        path = ""
    query = f"?{parsed.query}" if parsed.query else ""
    exact = f"{parsed.scheme}://{host}{path}{query}"

    clauses = []
    if host:
        clauses.append(f"page.domain:{host}")
        clauses.append(f"task.domain:{host}")
    if exact:
        clauses.append(f'page.url:"{exact}"')
        clauses.append(f'task.url:"{exact}"')
    rewritten = " OR ".join(clauses) if clauses else text
    note = f"treated URL as search: {rewritten}"
    return rewritten, note


def cmd_search(client: Client, args: argparse.Namespace) -> None:
    query = " ".join(args.query).strip()
    if not query:
        die("search query is empty")
    query, rewritten = normalize_search_query(query)
    if rewritten and not args.json:
        print(C.paint(f"  {rewritten}", C.dim))
        print()
    data = client.search(
        query,
        size=args.size,
        search_after=args.after,
        datasource=args.datasource,
    )
    if args.json:
        emit_json(data)
    else:
        print_search(data, query)
        print_rate(client)
    if args.save:
        Path(args.save).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(C.paint(f"  saved {args.save}", C.dim))


def cmd_scan(client: Client, args: argparse.Namespace) -> None:
    if not client.api_key:
        die("submitting a scan requires an API key (--api-key or URLSCAN_API_KEY)")
    tags = args.tag or []
    data = client.submit(
        args.url,
        visibility=args.visibility,
        country=args.country,
        tags=tags,
        customagent=args.user_agent,
        referer=args.referer,
        override_safety=args.override_safety,
    )
    if args.json and not args.wait:
        emit_json(data)
        return
    if not args.json:
        print_submission(data)
        print_rate(client)

    uuid = data.get("uuid")
    if args.wait:
        if not uuid:
            die("submission did not return a uuid")
        print()
        result = client.wait_for_result(
            uuid,
            timeout=args.timeout,
            initial_delay=args.initial_delay,
            interval=args.interval,
        )
        if args.json:
            emit_json(result)
        else:
            print_result_summary(result)
            print_rate(client)
        if args.save:
            Path(args.save).write_text(
                json.dumps(result, indent=2), encoding="utf-8"
            )
            print(C.paint(f"  saved {args.save}", C.dim))
    elif args.save:
        Path(args.save).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(C.paint(f"  saved {args.save}", C.dim))


def cmd_result(client: Client, args: argparse.Namespace) -> None:
    uuid = args.uuid.strip()
    try:
        if args.wait:
            data = client.wait_for_result(
                uuid,
                timeout=args.timeout,
                initial_delay=args.initial_delay,
                interval=args.interval,
            )
        else:
            data = client.result(uuid)
    except APIError as exc:
        if exc.status == 404:
            die(
                f"scan {uuid} is not ready yet (HTTP 404). "
                "Re-run with --wait, or wait ~10–30s and try again."
            )
        if exc.status == 410:
            die(f"scan {uuid} has been deleted (HTTP 410)")
        raise
    if args.json:
        emit_json(data)
    else:
        print_result_summary(data)
        print_rate(client)
    if args.save:
        Path(args.save).write_text(json.dumps(data, indent=2), encoding="utf-8")
        print(C.paint(f"  saved {args.save}", C.dim))


def cmd_screenshot(client: Client, args: argparse.Namespace) -> None:
    uuid = args.uuid.strip()
    out = Path(args.output or f"{uuid}.png")
    blob = client.download(f"{BASE}/screenshots/{uuid}.png")
    out.write_bytes(blob)
    print(C.paint(f"wrote {out} ({len(blob)} bytes)", C.bright_green))


def cmd_dom(client: Client, args: argparse.Namespace) -> None:
    uuid = args.uuid.strip()
    blob = client.download(f"{BASE}/dom/{uuid}/")
    text = blob.decode("utf-8", errors="replace")
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(C.paint(f"wrote {args.output} ({len(blob)} bytes)", C.bright_green))
    elif args.json:
        emit_json({"uuid": uuid, "dom": text})
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def cmd_quotas(client: Client, args: argparse.Namespace) -> None:
    data = client.quotas()
    if args.json:
        emit_json(data)
    else:
        print_quotas(data)


def cmd_whoami(client: Client, args: argparse.Namespace) -> None:
    if not client.api_key:
        die("whoami requires an API key")
    data = client.whoami()
    if args.json:
        emit_json(data)
    else:
        print_whoami(data)


def cmd_fields(_: Client, __: argparse.Namespace) -> None:
    print(C.paint("useful search fields", C.bold, C.bright_cyan))
    rows = [
        ("page.domain:example.com", "final page domain (includes subdomains)"),
        ("domain:example.com", "any contacted / tasked domain"),
        ("page.ip:1.2.3.4", "final page IP"),
        ("ip:1.2.3.4", "any contacted IP (CIDR: ip:1.2.3.0\\/24)"),
        ("asn:AS13335", "any contacted ASN"),
        ("hash:<sha256>", "resource hash"),
        ("filename:invoice.pdf", "downloaded filename"),
        ("server:nginx", "HTTP server banner"),
        ("country:us", "page country (ISO-3166 alpha-2)"),
        ("task.url:\"https://...\"", "originally tasked URL"),
        ("task.uuid:<uuid>", "exact scan id"),
        ("task.visibility:public", "public | unlisted | private"),
        ("task.tags:phishing", "submitter tags"),
        ("date:>now-7d", "relative time window (prefer this)"),
        ("date:[2026-01-01 TO 2026-02-01]", "absolute range"),
        ("stats.uniqIPs:>10", "numeric thresholds"),
        ("verdicts.malicious:true", "has a malicious verdict (plan-dependent)"),
    ]
    print()
    print(C.paint("  syntax", C.bold))
    print(f"  {C.dim}Elasticsearch query string. Default operator is AND.{C.reset}")
    print(f"  {C.dim}Group with ()  combine with AND / OR / NOT{C.reset}")
    print(f"  {C.dim}Escape reserved chars: + - = && || > < ! ( ) {{ }} [ ] ^ \" ~ * ? : \\ /{C.reset}")
    print()
    for field, note in rows:
        print(f"  {C.bright_white}{field:<42}{C.reset} {C.dim}{note}{C.reset}")
    print()
    print(C.paint("  examples", C.bold))
    examples = [
        "page.domain:paypal.com AND date:>now-1d",
        "domain:evil.tld AND country:ru AND date:>now-30d",
        "hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "task.tags:phishing AND verdicts.malicious:true",
    ]
    for ex in examples:
        print(f"  {C.cyan}{ex}{C.reset}")
    print()
    print(
        C.paint(
            "  full reference: https://docs.urlscan.io/pages/search-api-reference",
            C.dim,
        )
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="urlscan.py",
        description="Talk to the urlscan.io API from the command line.",
        epilog=(
            "Get a free API key at https://urlscan.io/user/signup then "
            "export URLSCAN_API_KEY=...  Search field reference: "
            "https://docs.urlscan.io/pages/search-api-reference"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--api-key",
        help="urlscan.io API key (overrides URLSCAN_API_KEY and config file)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print raw JSON instead of a colored summary",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors (also honors NO_COLOR)",
    )
    parser.add_argument(
        "--save",
        metavar="FILE",
        help="write the JSON response to FILE",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_search = sub.add_parser(
        "search",
        help="search historical scans (Elasticsearch query string)",
        description=(
            "Search public scans (and your own unlisted/private scans) using "
            "the same query language as the urlscan.io search box."
        ),
    )
    p_search.add_argument("query", nargs="+", help="query string, e.g. domain:example.com")
    p_search.add_argument(
        "--size",
        type=int,
        default=20,
        help="number of results (default 20, max depends on plan, up to 10000)",
    )
    p_search.add_argument(
        "--after",
        dest="after",
        help="pagination cursor from the previous page's sort value",
    )
    p_search.add_argument(
        "--datasource",
        choices=("scans", "hostnames", "incidents", "notifications", "certificates"),
        help="Pro datasources (default: scans)",
    )
    p_search.set_defaults(func=cmd_search)

    p_scan = sub.add_parser("scan", help="submit a URL to be scanned")
    p_scan.add_argument("url", help="full URL to scan, including scheme")
    p_scan.add_argument(
        "--visibility",
        choices=("public", "unlisted", "private"),
        help="result visibility (default: account setting)",
    )
    p_scan.add_argument(
        "--country",
        help="scan-from country as ISO-3166 alpha-2 (e.g. us, de, jp)",
    )
    p_scan.add_argument(
        "--tag",
        action="append",
        help="user tag (repeatable, max 10)",
    )
    p_scan.add_argument("--user-agent", help="override the browser User-Agent")
    p_scan.add_argument("--referer", help="override the HTTP Referer")
    p_scan.add_argument(
        "--override-safety",
        action="store_true",
        help="disable PII reclassification of the submitted URL",
    )
    p_scan.add_argument(
        "--wait",
        action="store_true",
        help="poll until the scan finishes and print the result",
    )
    p_scan.add_argument(
        "--wait-timeout",
        dest="timeout",
        type=float,
        default=120.0,
        help="max seconds to wait when --wait is set (default 120)",
    )
    p_scan.add_argument(
        "--initial-delay",
        type=float,
        default=10.0,
        help="seconds to wait before the first poll (default 10)",
    )
    p_scan.add_argument(
        "--interval",
        type=float,
        default=3.0,
        help="seconds between polls (default 3)",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_result = sub.add_parser("result", help="fetch a finished scan by UUID")
    p_result.add_argument("uuid", help="scan UUID from a submission or search hit")
    p_result.add_argument(
        "--wait",
        action="store_true",
        help="poll if the result is not ready yet (HTTP 404)",
    )
    p_result.add_argument(
        "--wait-timeout",
        dest="timeout",
        type=float,
        default=120.0,
        help="max seconds to wait when --wait is set (default 120)",
    )
    p_result.add_argument("--initial-delay", type=float, default=2.0)
    p_result.add_argument("--interval", type=float, default=3.0)
    p_result.set_defaults(func=cmd_result)

    p_shot = sub.add_parser("screenshot", help="download the PNG screenshot for a scan")
    p_shot.add_argument("uuid")
    p_shot.add_argument("-o", "--output", help="output path (default: <uuid>.png)")
    p_shot.set_defaults(func=cmd_screenshot)

    p_dom = sub.add_parser("dom", help="download the DOM snapshot for a scan")
    p_dom.add_argument("uuid")
    p_dom.add_argument("-o", "--output", help="write to FILE instead of stdout")
    p_dom.set_defaults(func=cmd_dom)

    p_quotas = sub.add_parser("quotas", help="show remaining API quotas")
    p_quotas.set_defaults(func=cmd_quotas)

    p_who = sub.add_parser("whoami", help="show the account attached to the API key")
    p_who.set_defaults(func=cmd_whoami)

    p_fields = sub.add_parser(
        "fields",
        help="cheat-sheet of useful search fields and example queries",
    )
    p_fields.set_defaults(func=cmd_fields)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    global C
    C = Palette(enabled=_want_color(args.no_color))

    client = Client(api_key=load_api_key(args.api_key), timeout=args.timeout)

    try:
        args.func(client, args)
    except APIError as exc:
        extra = ""
        if exc.status == 429 and exc.headers:
            rate = RateLimitInfo(exc.headers)
            if rate.reset_after is not None:
                extra = f" Retry after {rate.reset_after}s ({rate.summary()})."
            elif rate.present:
                extra = f" {rate.summary()}."
        if exc.status == 400 and args.command == "search":
            extra = (
                " Search uses Elasticsearch syntax, not a raw URL. "
                "Try: search page.domain:hackonlinemod.com   "
                "or: scan https://hackonlinemod.com"
            )
        if exc.status == 401:
            extra = " Check URLSCAN_API_KEY / --api-key."
        if exc.status == 403:
            extra = (
                " Result/DOM endpoints require a valid API key since May 2026."
            )
        die(f"{exc}{extra}")
    except KeyboardInterrupt:
        print(file=sys.stderr)
        die("interrupted", code=130)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
