"""Turn robots.txt and sitemaps into URLs for pulse.

Local files stay local. `--fetch` requests one http or https URL, and only
when that host is in scope (loopback always is). A redirect that leaves
scope is discarded. Nested sitemaps stop at ten. The URL list is stdout so
it can be piped; the short summary goes to stderr.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
from rich.console import Console
from rich.markup import escape

from hawk import VERSION, ui
from hawk.workspace import allowed, explain_block, hostname_of, remember_urls, scope_is_active, urls_path

_MAX_BYTES = 1_000_000
_MAX_SITEMAPS = 10
_MAX_REDIRECTS = 3
_TIMEOUT = 10.0
_REDIRECTS = {301, 302, 303, 307, 308}
_LOC = re.compile(r"<loc>\s*([^<]+?)\s*</loc>", re.IGNORECASE)


class ScopeError(Exception):
    def __init__(self, host: str) -> None:
        super().__init__(host)
        self.host = host


class FetchError(Exception):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk robots",
        description="Read robots.txt and sitemaps and print URLs pulse can check.",
    )
    parser.add_argument("inputs", nargs="*", help="Local robots.txt or sitemap files.")
    parser.add_argument("--base", help="Origin for relative paths, such as https://app.internal.")
    parser.add_argument("--fetch", help="Fetch this in-scope robots.txt or sitemap.")
    parser.add_argument("--save", help="Also write the URL list to this file.")
    parser.add_argument(
        "--no-workspace",
        action="store_true",
        help="Print every URL and leave the scope URL list unchanged.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.inputs and not args.fetch:
        _say("Give a local robots.txt or sitemap, or pass --fetch URL.")
        return 2
    base = (args.base or "").strip()
    if base and not _http_url(base):
        _say("Base needs an http or https URL, such as https://app.internal.")
        return 2
    use_scope = scope_is_active() and not args.no_workspace
    if base and use_scope and not allowed(base):
        _plain(explain_block(hostname_of(base) or base))
        return 2
    if args.fetch and not allowed(args.fetch):
        _plain(explain_block(hostname_of(args.fetch) or args.fetch))
        return 2

    found: list[str] = []
    skipped = 0
    for name in args.inputs:
        path = Path(name)
        if not path.is_file():
            _say(f"No file named {name}.")
            return 2
        text = path.read_text(encoding="utf-8", errors="replace")
        urls, missed = urls_from_text(text, base or None, client=None, budget=[_MAX_SITEMAPS], seen=set())
        found.extend(urls)
        skipped += missed

    if args.fetch:
        try:
            with _client() as client:
                text, final_url = fetch_document(client, args.fetch)
                fetch_base = base or origin_of(final_url)
                urls, missed = urls_from_text(
                    text,
                    fetch_base,
                    client=client,
                    budget=[_MAX_SITEMAPS],
                    seen=set(),
                )
        except ScopeError as exc:
            _plain(explain_block(exc.host))
            return 2
        except FetchError as exc:
            _say(str(exc))
            return 1
        found.extend(urls)
        skipped += missed

    unique = _unique(url for url in found if _http_url(url))
    if use_scope:
        kept = [url for url in unique if allowed(url)]
        dropped = len(unique) - len(kept)
        fresh = remember_urls(kept)
    else:
        kept = unique
        dropped = 0
        fresh = 0
    for url in kept:
        print(url)
    if args.save:
        try:
            Path(args.save).write_text("".join(url + "\n" for url in kept), encoding="utf-8")
        except OSError as exc:
            _say(f"Could not write {args.save}: {exc}")
            return 1
    _summary(len(kept), skipped, dropped, fresh, use_scope)
    return 0


def urls_from_text(
    text: str,
    base: str | None,
    *,
    client: httpx.Client | None,
    budget: list[int],
    seen: set[str],
) -> tuple[list[str], int]:
    """Return (urls, relative paths that had no base)."""
    if looks_like_sitemap(text):
        locs = [item for item in (resolve(loc, base) for loc in sitemap_locs(text)) if item]
        if client is not None and is_sitemap_index(text):
            return _fetch_sitemaps(locs, base, client, budget, seen), 0
        return locs, 0
    return robots_urls(text, base, client=client, budget=budget, seen=seen)


def looks_like_sitemap(text: str) -> bool:
    sample = text.lstrip()[:800].lower()
    return sample.startswith("<?xml") or "<urlset" in sample or "<sitemapindex" in sample or "<loc" in sample


def is_sitemap_index(text: str) -> bool:
    return "<sitemapindex" in text[:8000].lower()


def sitemap_locs(text: str) -> list[str]:
    found: list[str] = []
    for match in _LOC.finditer(text):
        value = html.unescape(match.group(1)).strip()
        if value:
            found.append(value)
    return found


def robots_urls(
    text: str,
    base: str | None,
    *,
    client: httpx.Client | None,
    budget: list[int],
    seen: set[str],
) -> tuple[list[str], int]:
    urls: list[str] = []
    sitemaps: list[str] = []
    skipped = 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "sitemap":
            resolved = resolve(value, base)
            if resolved:
                sitemaps.append(resolved)
            else:
                skipped += 1
            continue
        if key not in {"allow", "disallow"}:
            continue
        if key == "disallow" and value == "":
            continue
        path = _clean_robots_path(value)
        if not path:
            continue
        resolved = resolve(path, base)
        if resolved is None:
            skipped += 1
            continue
        urls.append(resolved)
    if client is None:
        urls.extend(sitemaps)
        return urls, skipped
    urls.extend(_fetch_sitemaps(sitemaps, base, client, budget, seen))
    return urls, skipped


def resolve(value: str, base: str | None) -> str | None:
    text = value.strip()
    if not text:
        return None
    if "://" in text:
        return text if _http_url(text) else None
    if not base:
        return None
    joined = urljoin(base if base.endswith("/") else base + "/", text)
    return joined if _http_url(joined) else None


def fetch_document(client: httpx.Client, url: str) -> tuple[str, str]:
    """Return (body, final URL). Raises ScopeError before an off-scope hop."""
    current = url
    for hop in range(_MAX_REDIRECTS + 1):
        host = hostname_of(current)
        if not host or not allowed(current):
            raise ScopeError(host or current)
        if not _http_url(current):
            raise FetchError("Only http and https URLs can be fetched.")
        try:
            with client.stream("GET", current) as response:
                if response.status_code in _REDIRECTS and hop < _MAX_REDIRECTS:
                    location = response.headers.get("location", "").strip()
                    _drain(response, 65_536)
                    if location:
                        current = urljoin(current, location)
                        continue
                body = _drain(response, _MAX_BYTES)
        except httpx.HTTPError as exc:
            raise FetchError(f"Could not fetch {current}: {exc}") from exc
        return body.decode("utf-8", errors="replace"), current
    raise FetchError(f"Could not fetch {url}: too many redirects.")


def origin_of(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    if parts.port:
        host = f"{host}:{parts.port}"
    return f"{parts.scheme}://{host}"


def _fetch_sitemaps(
    locs: list[str],
    base: str | None,
    client: httpx.Client,
    budget: list[int],
    seen: set[str],
) -> list[str]:
    pages: list[str] = []
    for loc in locs:
        if loc in seen:
            continue
        if budget[0] <= 0 or not allowed(loc):
            if allowed(loc) or not scope_is_active():
                pages.append(loc)
            continue
        seen.add(loc)
        budget[0] -= 1
        try:
            child, final_url = fetch_document(client, loc)
        except ScopeError:
            continue
        except FetchError:
            pages.append(loc)
            continue
        nested, _skipped = urls_from_text(
            child,
            base or origin_of(final_url),
            client=client,
            budget=budget,
            seen=seen,
        )
        pages.extend(nested)
    return pages


def _clean_robots_path(value: str) -> str:
    text = value.strip()
    if text.endswith("$"):
        text = text[:-1].rstrip()
    if text.endswith("*"):
        text = text[:-1].rstrip()
    if not text or text == "*":
        return ""
    return text


def _http_url(url: str) -> bool:
    parts = urlsplit(url.strip())
    return parts.scheme in {"http", "https"} and bool(parts.hostname)


def _unique(urls) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        ordered.append(url)
    return ordered


def _client() -> httpx.Client:
    # trust_env is off so the host that was allowed is the host that is contacted.
    return httpx.Client(
        timeout=_TIMEOUT,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": f"WebHawk/{VERSION}", "Accept-Encoding": "identity"},
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


def _summary(kept: int, skipped: int, dropped: int, fresh: int, use_scope: bool) -> None:
    parts = [f"{kept} URL(s)"]
    if skipped:
        parts.append(f"{skipped} relative path(s) need --base")
    if dropped:
        parts.append(f"{dropped} outside scope")
    if use_scope:
        parts.append(f"{fresh} new in {urls_path().name}")
    _plain("  ".join(parts))


def _say(message: str) -> None:
    _err().print(f"[err]{escape(message)}[/err]")


def _plain(message: str) -> None:
    _err().print(message, markup=False, highlight=False)


def _err() -> Console:
    return Console(file=sys.stderr, theme=ui.THEME, highlight=False, force_terminal=False)
