"""List form fields and query parameters on a page.

A local HTML file stays local. A URL is fetched with one normal GET, and
only when that host is in scope (loopback always is). A redirect that leaves
scope is discarded. The module records fields a tester would review. It does
not change the query, send a second request, or add a payload. `--save`
writes the form as a raw request repeater can open.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
from rich.console import Console
from rich.markup import escape

from hawk import VERSION, ui
from hawk.session import apply_headers
from hawk.workspace import allowed, explain_block, hostname_of, requests_dir, save_request, scope_is_active

_MAX_BYTES = 1_000_000
_MAX_REDIRECTS = 3
_MAX_FIELDS = 200
_MAX_LINKS = 200
_MAX_SAVED = 40
_DEFAULT_LIMIT = 20
_REDIRECTS = {301, 302, 303, 307, 308}
_INTERESTING = {
    "id",
    "uid",
    "user",
    "userid",
    "username",
    "email",
    "account",
    "search",
    "q",
    "query",
    "sort",
    "order",
    "orderby",
    "filter",
    "category",
    "cat",
    "item",
    "product",
    "report",
    "page",
    "offset",
    "limit",
    "column",
    "table",
    "field",
    "where",
}
_DB_MARKERS = (
    ("you have an error in your sql syntax", "MySQL syntax error"),
    ("warning: mysql", "MySQL warning"),
    ("mysql_fetch", "MySQL error"),
    ("mysqli_", "MySQL error"),
    ("pg_query()", "PostgreSQL error"),
    ("psqlexception", "PostgreSQL error"),
    ("sqlite3.operationalerror", "SQLite error"),
    ("unclosed quotation mark after the character string", "SQL Server error"),
    ("microsoft ole db provider for odbc drivers", "ODBC error"),
    ("ora-00933", "Oracle error"),
    ("ora-01756", "Oracle error"),
    ("sqlstate[", "SQLSTATE error"),
)


class ScopeError(Exception):
    def __init__(self, host: str) -> None:
        super().__init__(host)
        self.host = host


class FetchError(Exception):
    pass


@dataclass
class Finding:
    method: str
    url: str
    name: str
    source: str
    note: str


@dataclass
class Draft:
    method: str
    url: str
    body: str


@dataclass
class Page:
    findings: list[Finding] = field(default_factory=list)
    drafts: list[Draft] = field(default_factory=list)
    unresolved: int = 0
    db_note: str = ""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk forms",
        description="List form fields and query parameters. Does not send a modified request.",
    )
    parser.add_argument("inputs", nargs="*", help="Local HTML file, or a file of http(s) URLs.")
    parser.add_argument("--url", action="append", default=[], help="Fetch this in-scope page with a normal GET.")
    parser.add_argument("--base", help="Page URL used to resolve relative links in a local file.")
    parser.add_argument(
        "--save",
        dest="save_requests",
        action="store_true",
        help="Write an in-scope raw request for each form and link under .webhawk/requests/.",
    )
    parser.add_argument(
        "--no-workspace",
        action="store_true",
        help="List every parsed URL and do not apply the scope filter.",
    )
    parser.add_argument("--limit", type=int, default=_DEFAULT_LIMIT, help="Maximum pages to fetch. Default 20.")
    parser.add_argument("--timeout", type=float, default=10, help="Seconds to wait for each page.")
    parser.add_argument("--cookie", default=None, help="Cookie for this run. Replaces the saved session cookie.")
    parser.add_argument(
        "--authorization",
        default=None,
        help="Authorization for this run. Replaces the saved session value.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit < 1:
        _say("Limit has to be at least 1.")
        return 2
    if args.timeout <= 0:
        _say("Timeout has to be greater than 0.")
        return 2
    base = (args.base or "").strip()
    if base and not _http_url(base):
        _say("Base needs an http or https URL, such as https://app.internal/app.")
        return 2
    use_scope = scope_is_active() and not args.no_workspace
    if base and use_scope and not allowed(base):
        _plain(explain_block(hostname_of(base) or base))
        return 2
    if args.save_requests and not scope_is_active():
        _say("No scope workspace yet. Run: webhawk scope init")
        return 2

    try:
        files, page_urls = _collect_inputs(args.inputs, args.url)
    except ValueError as exc:
        _say(str(exc))
        return 2
    if not files and not page_urls:
        _say("Give a local HTML file, a file of URLs, or --url.")
        return 2

    findings: list[Finding] = []
    drafts: list[Draft] = []
    unresolved = 0
    dropped = 0
    blocked: list[str] = []
    fetched = 0
    allowed_urls = []
    for url in _unique(page_urls):
        if not allowed(url):
            blocked.append(hostname_of(url) or url)
            continue
        allowed_urls.append(url)
    if page_urls and not allowed_urls and not files:
        _plain(explain_block(blocked[0]))
        return 2

    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _say(f"Could not read {path}: {exc}")
            return 1
        if len(text.encode("utf-8", errors="replace")) > _MAX_BYTES:
            text = text[:_MAX_BYTES]
        page = parse_document(text[:_MAX_BYTES], base or None, page_url=base or path.name)
        kept, skipped = _filter_page(page, use_scope)
        findings.extend(kept.findings)
        drafts.extend(kept.drafts)
        unresolved += kept.unresolved
        dropped += skipped

    if allowed_urls:
        try:
            with _client(args.timeout, cookie=args.cookie, authorization=args.authorization) as client:
                for url in allowed_urls:
                    if fetched >= args.limit:
                        _plain(f"Stopped after {args.limit} page(s).")
                        break
                    fetched += 1
                    text, final_url = fetch_document(client, url)
                    page = parse_document(text, final_url, page_url=final_url)
                    kept, skipped = _filter_page(page, use_scope)
                    findings.extend(kept.findings)
                    drafts.extend(kept.drafts)
                    unresolved += kept.unresolved
                    dropped += skipped
        except ScopeError as exc:
            _plain(explain_block(exc.host))
            return 2
        except FetchError as exc:
            _say(str(exc))
            return 1

    findings = _unique_findings(findings)
    if len(findings) > _MAX_FIELDS:
        findings = findings[:_MAX_FIELDS]
        _plain(f"Stopped after {_MAX_FIELDS} fields.")
    _print_findings(findings)
    saved = 0
    if args.save_requests:
        try:
            saved = _save_drafts(drafts)
        except ValueError as exc:
            _say(str(exc))
            return 2
    _summary(len(findings), unresolved, dropped, len(blocked), saved)
    if page_urls and not findings and blocked and not files:
        return 2
    return 0


def parse_document(text: str, base: str | None, *, page_url: str) -> Page:
    """Parse one HTML document. `base` resolves relative links. Nothing is fetched."""
    parser = _Parser()
    parser.feed(text)
    parser.close()
    page = Page()
    page.db_note = database_note(text)
    resolve_base = base
    if parser.base_href:
        resolved = _resolve(parser.base_href, base)
        if isinstance(resolved, str) and resolved:
            resolve_base = resolved
        elif resolved is None and parser.base_href.strip():
            page.unresolved += 1
    if page.db_note:
        page.findings.append(Finding("NOTE", page_url, "-", "database", page.db_note))
    for form in parser.forms:
        if form["action"]:
            target = _resolve(form["action"], resolve_base)
        elif resolve_base:
            target = resolve_base
        else:
            target = None
        if target is None:
            page.unresolved += 1
            continue
        if not target:
            continue
        named = [item for item in form["fields"] if item["name"]][:40]
        if not named:
            continue
        method = form["method"] if form["method"] in {"GET", "POST", "PUT", "PATCH"} else "GET"
        for item in named:
            page.findings.append(
                Finding(method, target, item["name"], "form", _field_note(item))
            )
        url, body = _form_request(target, method, named)
        page.drafts.append(Draft(method, url, body))
    seen_links: set[str] = set()
    for href in parser.links[:_MAX_LINKS]:
        if "?" not in href:
            continue
        target = _resolve(href, resolve_base)
        if target is None:
            page.unresolved += 1
            continue
        if not target or target in seen_links:
            continue
        pairs = parse_qsl(urlsplit(target).query, keep_blank_values=True)
        if not pairs:
            continue
        seen_links.add(target)
        seen_names: set[str] = set()
        for name, _value in pairs:
            if not name or name in seen_names:
                continue
            seen_names.add(name)
            page.findings.append(Finding("GET", target, name, "link", _interest_note(name)))
        page.drafts.append(Draft("GET", target, ""))
    return page


def database_note(text: str) -> str:
    """Return a short label when the untouched page already shows a database error."""
    lowered = text.lower()
    for needle, label in _DB_MARKERS:
        if needle in lowered:
            return label
    return ""


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
            raise FetchError(f"Could not fetch {current}: {exc.__class__.__name__}") from exc
        return body.decode("utf-8", errors="replace"), current
    raise FetchError(f"Could not fetch {url}: too many redirects.")


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self.links: list[str] = []
        self.base_href = ""
        self._form: dict | None = None
        self._select: dict | None = None
        self._textarea: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs)
        if tag == "textarea":
            self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            self._textarea["value"] += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "textarea" and self._textarea is not None and self._form is not None:
            self._form["fields"].append(self._textarea)
            self._textarea = None
        elif tag == "select" and self._select is not None and self._form is not None:
            self._form["fields"].append(
                {"name": self._select["name"], "type": "select", "value": self._select["value"], "disabled": False}
            )
            self._select = None
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
            self._select = None
            self._textarea = None

    def close(self) -> None:
        super().close()
        if self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def _start(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {name.lower(): value or "" for name, value in attrs}
        flags = {name.lower() for name, _value in attrs}
        if tag == "base" and not self.base_href:
            self.base_href = attr.get("href", "").strip()
            return
        if tag == "form":
            if self._form is not None:
                self.forms.append(self._form)
            self._form = {
                "action": attr.get("action", "").strip(),
                "method": (attr.get("method") or "GET").strip().upper() or "GET",
                "fields": [],
            }
            self._select = None
            self._textarea = None
            return
        if tag == "a":
            href = attr.get("href", "").strip()
            if href:
                self.links.append(href)
            return
        if tag in {"area", "iframe"}:
            href = (attr.get("href") or attr.get("src") or "").strip()
            if href and "?" in href:
                self.links.append(href)
            return
        if self._form is None:
            return
        if tag == "input":
            name = attr.get("name", "").strip()
            if not name:
                return
            self._form["fields"].append(
                {
                    "name": name,
                    "type": (attr.get("type") or "text").strip().lower() or "text",
                    "value": attr.get("value", ""),
                    "disabled": "disabled" in flags,
                }
            )
        elif tag == "textarea":
            name = attr.get("name", "").strip()
            if name:
                self._textarea = {"name": name, "type": "textarea", "value": "", "disabled": "disabled" in flags}
        elif tag == "select":
            name = attr.get("name", "").strip()
            if name:
                self._select = {"name": name, "value": "", "chosen": False}
        elif tag == "option" and self._select is not None:
            selected = "selected" in flags
            if selected or not self._select["chosen"]:
                self._select["value"] = attr.get("value", "")
                if selected:
                    self._select["chosen"] = True
        elif tag == "button":
            name = attr.get("name", "").strip()
            if name:
                self._form["fields"].append(
                    {
                        "name": name,
                        "type": "button",
                        "value": attr.get("value", ""),
                        "disabled": "disabled" in flags,
                    }
                )


def _form_request(action: str, method: str, fields: list[dict]) -> tuple[str, str]:
    pairs = []
    for item in fields:
        if item.get("disabled"):
            continue
        value = "" if item["type"] == "password" else item.get("value", "")
        pairs.append((item["name"], value))
    if method == "GET":
        parts = urlsplit(action)
        existing = parse_qsl(parts.query, keep_blank_values=True)
        query = urlencode(existing + pairs, doseq=True)
        url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))
        return url, ""
    return action, urlencode(pairs, doseq=True)


def _field_note(item: dict) -> str:
    notes: list[str] = []
    kind = item.get("type", "")
    if kind == "hidden":
        notes.append("hidden")
    if kind == "password":
        notes.append("password")
    if item.get("disabled"):
        notes.append("disabled")
    interest = _interest_note(item.get("name", ""))
    if interest:
        notes.append(interest)
    return ", ".join(notes)


def _interest_note(name: str) -> str:
    key = name.strip().lower()
    if key in _INTERESTING or key.endswith("_id") or key.endswith("-id"):
        return "review"
    return ""


def _filter_page(page: Page, use_scope: bool) -> tuple[Page, int]:
    if not use_scope:
        return page, 0
    kept = Page(unresolved=page.unresolved, db_note=page.db_note)
    dropped = 0
    for item in page.findings:
        if item.method == "NOTE" or allowed(item.url):
            kept.findings.append(item)
        else:
            dropped += 1
    for draft in page.drafts:
        if allowed(draft.url):
            kept.drafts.append(draft)
        else:
            dropped += 1
    return kept, dropped


def _save_drafts(drafts: list[Draft]) -> int:
    chosen: list[Draft] = []
    seen: set[tuple[str, str, str]] = set()
    for draft in drafts:
        if not allowed(draft.url):
            continue
        if not _http_url(draft.url):
            continue
        key = (draft.method, draft.url, draft.body)
        if key in seen:
            continue
        seen.add(key)
        chosen.append(draft)
        if len(chosen) >= _MAX_SAVED:
            break
    saved = 0
    for draft, name in zip(chosen, _request_names(len(chosen))):
        save_request(name, render_request(draft))
        _plain(f"saved {name}")
        saved += 1
    if len(drafts) > len(chosen) and len(chosen) >= _MAX_SAVED:
        _plain(f"Stopped after {_MAX_SAVED} saved requests.")
    return saved


def render_request(draft: Draft) -> bytes:
    parts = urlsplit(draft.url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if parts.port:
        host = f"{host}:{parts.port}"
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    lines = [
        f"{draft.method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: WebHawk/{VERSION}",
    ]
    body = b""
    if draft.method != "GET":
        body = draft.body.encode("utf-8")
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(body)}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("latin-1", errors="replace") + body


def _request_names(count: int) -> list[str]:
    used = set()
    root = requests_dir()
    if root.is_dir():
        used = {path.name for path in root.glob("form-*.http")}
    names: list[str] = []
    number = 1
    while len(names) < count and number < 100000:
        candidate = f"form-{number:04d}.http"
        number += 1
        if candidate in used:
            continue
        used.add(candidate)
        names.append(candidate)
    return names


def _collect_inputs(inputs: list[str], urls: list[str]) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    found = [item.strip() for item in urls if item.strip()]
    for item in inputs:
        text = item.strip()
        if _http_url(text):
            found.append(text)
            continue
        path = Path(text)
        if not path.is_file():
            raise ValueError(f"No file named {text}.")
        sample = path.read_text(encoding="utf-8", errors="replace")[:8000]
        if _looks_like_html(sample):
            files.append(path)
            continue
        listed, bad = _url_lines(path)
        if bad or not listed:
            raise ValueError(f"{text} is not HTML and is not a list of http(s) URLs.")
        found.extend(listed)
    return files, found


def _looks_like_html(sample: str) -> bool:
    lowered = sample.lower()
    return any(token in lowered for token in ("<form", "<input", "<html", "<a ", "<a>", "<base"))


def _url_lines(path: Path) -> tuple[list[str], int]:
    urls: list[str] = []
    bad = 0
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _http_url(line):
            urls.append(line)
        else:
            bad += 1
    return urls, bad


def _resolve(ref: str, base: str | None) -> str | None:
    """Return a URL, '' when the reference is not a link, or None when it needs a base."""
    text = (ref or "").strip()
    if not text or text.startswith("#"):
        return ""
    scheme = text.split(":", 1)[0].lower() if ":" in text else ""
    if scheme and scheme not in {"http", "https"}:
        return ""
    if _http_url(text):
        return text
    if not base:
        return None
    joined = urljoin(base, text)
    return joined if _http_url(joined) else None


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        return
    print("method\turl\tname\tsource\tnote")
    for item in findings:
        print("\t".join((_cell(item.method), _cell(item.url), _cell(item.name), _cell(item.source), _cell(item.note))))


def _cell(value: str) -> str:
    return " ".join(value.replace("\t", " ").splitlines()).strip()


def _unique_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    ordered: list[Finding] = []
    for item in findings:
        key = (item.method, item.url, item.name, item.source)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)
    return ordered


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _http_url(url: str) -> bool:
    parts = urlsplit(url.strip())
    return parts.scheme in {"http", "https"} and bool(parts.hostname)


def _summary(fields: int, unresolved: int, dropped: int, blocked: int, saved: int) -> None:
    parts = [f"{fields} field(s)"]
    if unresolved:
        parts.append(f"{unresolved} relative link(s) need --base")
    if dropped:
        parts.append(f"{dropped} outside scope")
    if blocked:
        parts.append(f"{blocked} page(s) outside scope")
    if saved:
        parts.append(f"{saved} request(s) saved")
    _plain("  ".join(parts))


def _client(
    timeout: float,
    *,
    cookie: str | None = None,
    authorization: str | None = None,
) -> httpx.Client:
    # trust_env is off so the host that was allowed is the host that is contacted.
    headers = apply_headers(
        {"User-Agent": f"WebHawk/{VERSION}", "Accept-Encoding": "identity"},
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


def _say(message: str) -> None:
    _err().print(f"[err]{escape(message)}[/err]")


def _plain(message: str) -> None:
    _err().print(message, markup=False, highlight=False)


def _err() -> Console:
    return Console(file=sys.stderr, theme=ui.THEME, highlight=False, force_terminal=False)
