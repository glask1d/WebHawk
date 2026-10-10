"""Spider one site for endpoints.

Point silk at an http or https URL. It stays on that scheme, host, and port.
It reads links, forms, scripts, and stylesheets from each page, then reads
robots.txt and sitemap.xml. Paths named by robots.txt are listed and not
requested. A link that leaves the server is skipped. Stdout is one URL per
line, or a colored source and URL when the terminal can show color.
"""

from __future__ import annotations

import argparse
import html
import os
import re
import sys
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from rich.console import Console
from rich.markup import escape

from hawk import VERSION, ui
from hawk.session import apply_headers
from hawk.workspace import allowed, explain_block, hostname_of, remember_urls, scope_is_active, urls_path

_MAX_BYTES = 1_000_000
_MAX_REDIRECTS = 3
_MAX_ENDPOINTS = 500
_MAX_PER_PAGE = 200
_MAX_SITEMAPS = 8
_DEFAULT_LIMIT = 40
_DEFAULT_DEPTH = 2
_REDIRECTS = {301, 302, 303, 307, 308}
_PAGE_EXT = {"html", "htm", "php", "asp", "aspx", "jsp", "js", "mjs", "css", "xml", "txt", "json", "xhtml"}
_SKIP_EXT = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "webp",
    "svg",
    "ico",
    "bmp",
    "avif",
    "woff",
    "woff2",
    "ttf",
    "eot",
    "otf",
    "mp3",
    "mp4",
    "wav",
    "webm",
    "ogg",
    "pdf",
    "zip",
    "gz",
    "tgz",
    "rar",
    "7z",
    "tar",
    "bz2",
    "wasm",
    "map",
}
_LOC = re.compile(r"<loc>\s*([^<]+?)\s*</loc>", re.IGNORECASE)
_QUOTED = re.compile(r"""['"](https?://[^'"\s<>]{1,500}|/(?!/)[A-Za-z0-9._~%+\-/]{1,200})['"]""")
_CSS_URL = re.compile(
    r"""url\(\s*['"]?(https?://[^)'"\s<>]{1,500}|/(?!/)[A-Za-z0-9._~%+\-/]{1,200})['"]?\s*\)""",
    re.IGNORECASE,
)
_META_URL = re.compile(r"url\s*=\s*['\"]?([^'\";\s>]+)", re.IGNORECASE)
_ART = (
    r"         \    ^    /",
    r"       .  \   |   /  .",
    r"     (     \  |  /     )",
    r"      ' .   --+--   . '",
    "         /    |    \\",
    "        /     |     \\",
    r"           silk",
)
_CYAN = "\033[1;96m"
_YELLOW = "\033[1;93m"
_MAGENTA = "\033[1;95m"
_WHITE = "\033[1;97m"
_DIM = "\033[2;96m"
_RESET = "\033[0m"
_SOURCE_COLOR = {
    "start": "\033[1;95m",
    "link": "\033[1;96m",
    "form": "\033[1;93m",
    "script": "\033[1;94m",
    "style": "\033[1;92m",
    "robots": "\033[1;32m",
    "sitemap": "\033[1;33m",
    "asset": "\033[2m",
}


class ScopeError(Exception):
    def __init__(self, host: str) -> None:
        super().__init__(host)
        self.host = host


class FetchError(Exception):
    pass


@dataclass
class Response:
    status: int
    content_type: str
    body: str
    url: str
    left: bool


@dataclass
class Job:
    url: str
    depth: int
    source: str
    kind: str


@dataclass
class Result:
    endpoints: list[tuple[str, str]] = field(default_factory=list)
    fetched: int = 0
    off_host: int = 0
    left_server: int = 0
    stopped: str = ""
    robots_missing: bool = False
    sitemap_missing: bool = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk silk",
        description=(
            "Spider one in-scope site. Collect endpoints from pages, robots.txt, "
            "and sitemap.xml. Does not leave that scheme, host, and port."
        ),
    )
    parser.add_argument("url", help="Page to start from. Loopback is always in scope.")
    parser.add_argument("--depth", type=int, default=_DEFAULT_DEPTH, help="Link depth to follow. Default: 2.")
    parser.add_argument(
        "--limit",
        type=int,
        default=_DEFAULT_LIMIT,
        help="Maximum pages to fetch, including robots.txt and sitemaps. Default: 40.",
    )
    parser.add_argument("--timeout", type=float, default=10.0, help="Seconds for each request. Default: 10.")
    parser.add_argument("--save", help="Also write the URL list to this file.")
    parser.add_argument(
        "--no-workspace",
        action="store_true",
        help="Leave the scope URL list unchanged.",
    )
    parser.add_argument("--plain", action="store_true", help="Print one URL per line and skip the spider.")
    parser.add_argument("--cookie", default=None, help="Cookie for this run. Replaces the saved session cookie.")
    parser.add_argument(
        "--authorization",
        default=None,
        help="Authorization for this run. Replaces the saved session value.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit < 1 or args.depth < 0 or args.timeout <= 0:
        _say("Depth must be 0 or more. Limit and timeout must be greater than 0.")
        return 2
    start = canonicalize(args.url.strip())
    if start is None:
        _say("Give an http or https URL, such as http://127.0.0.1/.")
        return 2
    if not allowed(start):
        _plain(explain_block(hostname_of(start) or start))
        return 2
    origin = origin_key(start)
    if origin is None:
        _say("Give an http or https URL, such as http://127.0.0.1/.")
        return 2
    if not args.plain:
        _show_banner()
    try:
        with _client(args.timeout, cookie=args.cookie, authorization=args.authorization) as client:
            result = crawl(client, start, origin, depth=args.depth, limit=args.limit)
    except ScopeError as exc:
        _plain(explain_block(exc.host))
        return 2
    except FetchError as exc:
        _say(str(exc))
        return 1

    color_out = _color(sys.stdout) and not args.plain
    lines = [format_row(source, url, color_out) for url, source in result.endpoints]
    for line in lines:
        print(line)
    if args.save:
        try:
            Path(args.save).write_text("".join(url + "\n" for url, _source in result.endpoints), encoding="utf-8")
        except OSError as exc:
            _say(f"Could not write {args.save}: {exc}")
            return 1
    fresh = 0
    use_scope = scope_is_active() and not args.no_workspace
    if use_scope:
        fresh = remember_urls([url for url, _source in result.endpoints if allowed(url)])
    _summary(result, fresh, use_scope)
    return 0


def crawl(client: httpx.Client, start: str, origin: tuple[str, str, int], *, depth: int, limit: int) -> Result:
    result = Result()
    queued: set[str] = set()
    known: set[str] = set()
    queue: deque[Job] = deque()
    budget = {"maps": 0}
    tried_sitemap = False

    def remember(url: str, source: str) -> None:
        if url in known or len(result.endpoints) >= _MAX_ENDPOINTS:
            if url not in known and len(result.endpoints) >= _MAX_ENDPOINTS:
                result.stopped = result.stopped or f"Stopped after {_MAX_ENDPOINTS} endpoints."
            return
        known.add(url)
        result.endpoints.append((url, source))

    def enqueue(url: str, hop: int, source: str, kind: str) -> None:
        if not url or url in queued or origin_key(url) != origin or not allowed(url):
            return
        if kind == "seed-sitemap" and budget["maps"] >= _MAX_SITEMAPS:
            return
        if kind == "seed-sitemap":
            budget["maps"] += 1
        queued.add(url)
        queue.append(Job(url, hop, source, kind))

    remember(start, "start")
    enqueue(start, 0, "start", "page")
    root = origin_of(start) or ""
    enqueue(canonicalize(root + "/robots.txt") or "", 0, "robots", "seed-robots")
    enqueue(canonicalize(root + "/sitemap.xml") or "", 0, "sitemap", "seed-sitemap")

    while queue:
        if result.fetched >= limit:
            result.stopped = result.stopped or f"Stopped after {limit} pages."
            break
        if len(result.endpoints) >= _MAX_ENDPOINTS:
            result.stopped = result.stopped or f"Stopped after {_MAX_ENDPOINTS} endpoints."
            break
        job = queue.popleft()
        if job.kind == "seed-sitemap":
            tried_sitemap = True
        try:
            response = fetch_page(client, job.url, origin)
        except FetchError:
            if job.source == "start" and result.fetched == 0:
                raise
            if job.kind == "seed-robots":
                result.robots_missing = True
            continue
        result.fetched += 1
        if response.left:
            result.left_server += 1
            continue
        final = canonicalize(response.url) or job.url
        if job.kind == "seed-robots":
            if response.status != 200 or not _looks_like_robots(response.body):
                result.robots_missing = True
                continue
            remember(final, "robots")
            _take_robots(response.body, final, remember, enqueue, result)
            continue
        if job.kind == "seed-sitemap" and response.status == 200 and _looks_like_sitemap(response.body):
            remember(final, "sitemap")
            _take_sitemap(response.body, final, job.depth, depth, remember, enqueue, result)
            continue
        if job.kind.startswith("seed"):
            continue
        if final != job.url:
            remember(final, job.source)
        if response.status >= 400 or not response.body:
            continue
        _take_body(response, final, job.depth, depth, remember, enqueue, result)

    if tried_sitemap and not any(source == "sitemap" for _url, source in result.endpoints):
        result.sitemap_missing = True
    return result


def fetch_page(client: httpx.Client, url: str, origin: tuple[str, str, int]) -> Response:
    """GET one URL. A redirect that leaves the origin or scope is not followed."""
    current = url
    for hop in range(_MAX_REDIRECTS + 1):
        if origin_key(current) != origin:
            return Response(0, "", "", url, left=True)
        host = hostname_of(current)
        if not host or not allowed(current):
            raise ScopeError(host or current)
        try:
            with client.stream("GET", current) as response:
                status = response.status_code
                ctype = response.headers.get("content-type", "")
                if status in _REDIRECTS and hop < _MAX_REDIRECTS:
                    location = response.headers.get("location", "").strip()
                    _drain(response, 65_536)
                    if not location:
                        return Response(status, ctype, "", current, left=False)
                    nxt = urljoin(current, location)
                    if origin_key(nxt) != origin or not allowed(nxt):
                        return Response(status, ctype, "", current, left=True)
                    current = nxt
                    continue
                body = _drain(response, _MAX_BYTES)
        except httpx.HTTPError as exc:
            raise FetchError(f"Could not fetch {current}: {exc.__class__.__name__}") from exc
        return Response(status, ctype, body.decode("utf-8", errors="replace"), current, left=False)
    raise FetchError(f"Could not fetch {url}: too many redirects.")


def extract_html(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Return (base href, references as (value, source))."""
    parser = _Parser()
    parser.feed(text)
    parser.close()
    return parser.base_href, parser.found[:_MAX_PER_PAGE]


def extract_code(text: str) -> list[str]:
    """Quoted URLs and root paths from a script or stylesheet."""
    sample = text[:200_000]
    found: list[str] = []
    seen: set[str] = set()
    for match in _QUOTED.finditer(sample):
        _push_ref(found, seen, match.group(1))
    for match in _CSS_URL.finditer(sample):
        _push_ref(found, seen, match.group(1))
    return found[:_MAX_PER_PAGE]


def parse_robots(text: str) -> tuple[list[str], list[str]]:
    """Return (allow/disallow paths, sitemap URLs)."""
    paths: list[str] = []
    sitemaps: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "sitemap" and value:
            sitemaps.append(value)
            continue
        if key not in {"allow", "disallow"}:
            continue
        if key == "disallow" and value == "":
            continue
        path = _clean_robots_path(value)
        if path:
            paths.append(path)
    return paths, sitemaps


def sitemap_locs(text: str) -> list[str]:
    found: list[str] = []
    for match in _LOC.finditer(text):
        value = html.unescape(match.group(1)).strip()
        if value:
            found.append(value)
    return found


def canonicalize(url: str) -> str | None:
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    host = parts.hostname.lower().rstrip(".")
    if ":" in host:
        host = f"[{host}]"
    default = 443 if parts.scheme == "https" else 80
    netloc = host if parts.port in (None, default) else f"{host}:{parts.port}"
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def origin_key(url: str) -> tuple[str, str, int] | None:
    parts = urlsplit(url.strip())
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme.lower(), parts.hostname.lower().rstrip("."), port


def origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def format_banner(color: bool) -> str:
    lines: list[str] = []
    for line in _ART:
        if not color:
            lines.append(line)
            continue
        if "silk" in line:
            left, _, right = line.partition("silk")
            lines.append(f"{_CYAN}{left}{_MAGENTA}silk{_CYAN}{right}{_RESET}")
            continue
        painted: list[str] = []
        for ch in line:
            if ch in "()":
                painted.append(f"{_YELLOW}{ch}{_CYAN}")
            else:
                painted.append(ch)
        lines.append(f"{_CYAN}{''.join(painted)}{_RESET}")
    tag = "spins pages, robots.txt, and sitemaps into endpoints"
    lines.append(f"{_DIM}{tag}{_RESET}" if color else tag)
    return "\n".join(lines)


def format_row(source: str, url: str, color: bool) -> str:
    if not color:
        return url
    paint = _SOURCE_COLOR.get(source, _CYAN)
    return f"  {paint}{source:<8}{_RESET} {_WHITE}{url}{_RESET}"


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href = ""
        self.found: list[tuple[str, str]] = []
        self._mode = ""
        self._buf: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tag(tag, attrs, close_script=False)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._tag(tag, attrs, close_script=True)

    def handle_data(self, data: str) -> None:
        if self._mode:
            self._buf.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self._mode == tag:
            source = "script" if tag == "script" else "style"
            for value in extract_code("".join(self._buf)):
                self._add(value, source)
            self._mode = ""
            self._buf = []

    def _tag(self, tag: str, attrs: list[tuple[str, str | None]], *, close_script: bool) -> None:
        attr = {name.lower(): value or "" for name, value in attrs}
        if tag == "base" and not self.base_href:
            self.base_href = attr.get("href", "").strip()
        elif tag in {"a", "area"}:
            self._add(attr.get("href", ""), "link")
        elif tag == "form":
            self._add(attr.get("action", ""), "form")
        elif tag in {"button", "input"}:
            self._add(attr.get("formaction", ""), "form")
        elif tag == "script":
            self._add(attr.get("src", ""), "script")
            if not close_script:
                self._mode = "script"
                self._buf = []
        elif tag == "link":
            kind = "style" if "stylesheet" in attr.get("rel", "").lower() else "link"
            self._add(attr.get("href", ""), kind)
        elif tag in {"iframe", "frame"}:
            self._add(attr.get("src", ""), "link")
        elif tag in {"img", "source", "video", "audio", "track"}:
            self._add(attr.get("src", ""), "asset")
        elif tag == "meta" and attr.get("http-equiv", "").lower() == "refresh":
            match = _META_URL.search(attr.get("content", ""))
            if match:
                self._add(match.group(1), "link")
        elif tag == "style" and not close_script:
            self._mode = "style"
            self._buf = []

    def _add(self, value: str, source: str) -> None:
        text = value.strip()
        if text and len(self.found) < _MAX_PER_PAGE:
            self.found.append((text, source))


def _take_body(
    response: Response,
    page: str,
    hop: int,
    max_depth: int,
    remember,
    enqueue,
    result: Result,
) -> None:
    kind = _kind(page, response.content_type, response.body)
    if kind == "html":
        base_href, refs = extract_html(response.body)
        base = page
        if base_href:
            resolved = _resolve(base_href, page)
            if resolved:
                base = resolved
        _take_refs(refs, base, hop, max_depth, remember, enqueue, result)
        return
    if kind == "code":
        source = "style" if page.lower().split("?", 1)[0].endswith(".css") or "css" in response.content_type.lower() else "script"
        refs = [(value, source) for value in extract_code(response.body)]
        _take_refs(refs, page, hop, max_depth, remember, enqueue, result)
        return
    if kind == "sitemap":
        _take_sitemap(response.body, page, hop, max_depth, remember, enqueue, result)


def _take_refs(refs, base: str, hop: int, max_depth: int, remember, enqueue, result: Result) -> None:
    for raw, source in refs:
        if _ignored_scheme(raw):
            continue
        url = _resolve(raw, base)
        if url is None:
            continue
        if origin_key(url) != origin_key(base):
            result.off_host += 1
            continue
        if not allowed(url):
            continue
        remember(url, "asset" if _extension(url) in _SKIP_EXT else source)
        if hop + 1 <= max_depth and _should_fetch(url):
            enqueue(url, hop + 1, source, "page")


def _take_robots(text: str, page: str, remember, enqueue, result: Result) -> None:
    paths, sitemaps = parse_robots(text)
    base = origin_of(page) or page
    for raw in paths:
        url = _resolve(raw, base)
        if url is None or origin_key(url) != origin_key(page) or not allowed(url):
            continue
        remember(url, "robots")
    for raw in sitemaps:
        url = _resolve(raw, base)
        if url is None or origin_key(url) != origin_key(page) or not allowed(url):
            if url and origin_key(url) != origin_key(page):
                result.off_host += 1
            continue
        enqueue(url, 0, "sitemap", "seed-sitemap")


def _take_sitemap(
    text: str,
    page: str,
    hop: int,
    max_depth: int,
    remember,
    enqueue,
    result: Result,
) -> None:
    index = "<sitemapindex" in text[:8000].lower()
    for raw in sitemap_locs(text)[:_MAX_PER_PAGE]:
        url = _resolve(raw, page)
        if url is None or origin_key(url) != origin_key(page) or not allowed(url):
            if url and origin_key(url) != origin_key(page):
                result.off_host += 1
            continue
        remember(url, "sitemap")
        if index:
            enqueue(url, hop, "sitemap", "seed-sitemap")
            continue
        if hop + 1 <= max_depth and _should_fetch(url):
            enqueue(url, hop + 1, "sitemap", "page")


def _resolve(value: str, base: str) -> str | None:
    text = value.strip()
    if not text or text.startswith("#") or text.startswith("//") or _ignored_scheme(text):
        return None
    return canonicalize(urljoin(base, text))


def _ignored_scheme(value: str) -> bool:
    head = value.split(":", 1)[0].lower()
    return head in {"javascript", "mailto", "data", "tel", "blob", "about"}


def _should_fetch(url: str) -> bool:
    ext = _extension(url)
    if ext in _SKIP_EXT:
        return False
    if ext == "":
        return True
    return ext in _PAGE_EXT


def _extension(url: str) -> str:
    path = urlsplit(url).path
    name = path.rsplit("/", 1)[-1]
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def _kind(url: str, content_type: str, body: str) -> str:
    ctype = content_type.lower()
    path = urlsplit(url).path.lower()
    if "javascript" in ctype or path.endswith((".js", ".mjs")):
        return "code"
    if "css" in ctype or path.endswith(".css"):
        return "code"
    if _looks_like_sitemap(body) and ("xml" in ctype or path.endswith(".xml") or "sitemap" in path):
        return "sitemap"
    if "html" in ctype or _looks_like_html(body):
        return "html"
    return "other"


def _looks_like_html(text: str) -> bool:
    sample = text.lstrip()[:600].lower()
    return any(token in sample for token in ("<!doctype", "<html", "<a ", "<a>", "<form", "<script", "<head", "<body"))


def _looks_like_sitemap(text: str) -> bool:
    sample = text.lstrip()[:800].lower()
    return "<urlset" in sample or "<sitemapindex" in sample or "<loc" in sample


def _looks_like_robots(text: str) -> bool:
    sample = text.lstrip()[:1000].lower()
    if sample.startswith("<"):
        return False
    return any(token in sample for token in ("user-agent", "disallow", "allow:", "sitemap:"))


def _clean_robots_path(value: str) -> str:
    text = value.strip()
    if text.endswith("$"):
        text = text[:-1].rstrip()
    if text.endswith("*"):
        text = text[:-1].rstrip()
    if not text or text == "*":
        return ""
    return text


def _push_ref(found: list[str], seen: set[str], value: str) -> None:
    if value in seen or value.startswith("//"):
        return
    seen.add(value)
    found.append(value)


def _client(
    timeout: float,
    *,
    cookie: str | None = None,
    authorization: str | None = None,
) -> httpx.Client:
    # trust_env is off so the host that was allowed is the host that is contacted.
    headers = apply_headers(
        {
            "User-Agent": f"WebHawk/{VERSION}",
            "Accept-Encoding": "identity",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        cookie=cookie,
        authorization=authorization,
    )
    return httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        headers=headers,
    )


def _drain(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        if total >= limit:
            break
        piece = chunk[: limit - total]
        chunks.append(piece)
        total += len(piece)
    return b"".join(chunks)


def _summary(result: Result, fresh: int, use_scope: bool) -> None:
    parts = [f"{len(result.endpoints)} endpoint(s)", f"{result.fetched} page(s)"]
    if result.off_host:
        parts.append(f"{result.off_host} left this server")
    if result.left_server:
        parts.append(f"{result.left_server} redirect(s) stayed put")
    if result.robots_missing:
        parts.append("no robots.txt")
    if result.sitemap_missing:
        parts.append("no sitemap.xml")
    if use_scope:
        parts.append(f"{fresh} new in {urls_path().name}")
    text = "  ".join(parts)
    if _color(sys.stderr):
        text = f"{_MAGENTA}silk{_RESET}  {text}"
    _plain(text)
    if result.stopped:
        _plain(result.stopped)


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
    Console(file=sys.stderr, theme=ui.THEME, highlight=False).print(f"[err]{escape(message)}[/err]")


def _plain(message: str) -> None:
    print(message, file=sys.stderr)
