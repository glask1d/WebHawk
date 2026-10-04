#!/usr/bin/env python3
"""
flowcarve.py
Carve URLs / endpoints out of mitmproxy dumps, HAR files, raw HTTP
responses, and plain text/HTML/JS/JSON bodies.

Examples:
  python3 flowcarve.py capture.mitm
  python3 flowcarve.py response.txt --save links.txt
  python3 flowcarve.py flows.har -o urls.json --format json
  python3 flowcarve.py dump.mitm --include-requests --sort --unique
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
from collections import Counter, OrderedDict
from html.parser import HTMLParser
from typing import Iterable, Iterator
from urllib.parse import unquote, urljoin, urlparse


# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

class Palette:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    BG_DARK = "\033[48;5;236m"

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def wrap(self, text: str, *codes: str) -> str:
        if not self.enabled or not text:
            return text
        return f"{''.join(codes)}{text}{self.RESET}"

    def title(self, text: str) -> str:
        return self.wrap(text, self.BOLD, self.BRIGHT_CYAN)

    def header(self, text: str) -> str:
        return self.wrap(text, self.BOLD, self.BRIGHT_WHITE)

    def ok(self, text: str) -> str:
        return self.wrap(text, self.BRIGHT_GREEN)

    def warn(self, text: str) -> str:
        return self.wrap(text, self.BRIGHT_YELLOW)

    def err(self, text: str) -> str:
        return self.wrap(text, self.RED)

    def dim(self, text: str) -> str:
        return self.wrap(text, self.DIM)

    def kind(self, kind: str, text: str) -> str:
        mapping = {
            "https": (self.BRIGHT_GREEN, self.BOLD),
            "http": (self.YELLOW, self.BOLD),
            "protocol-relative": (self.BRIGHT_CYAN,),
            "absolute-path": (self.BRIGHT_BLUE,),
            "relative-path": (self.BLUE,),
            "js-endpoint": (self.BRIGHT_MAGENTA,),
            "ws": (self.MAGENTA, self.BOLD),
            "wss": (self.MAGENTA, self.BOLD),
            "data": (self.DIM,),
            "mailto": (self.CYAN,),
            "other": (self.WHITE,),
            "request": (self.BRIGHT_YELLOW,),
            "header": (self.BRIGHT_CYAN,),
            "html": (self.GREEN,),
            "css": (self.BLUE,),
            "js": (self.MAGENTA,),
            "json": (self.YELLOW,),
            "regex": (self.WHITE,),
        }
        codes = mapping.get(kind, (self.WHITE,))
        return self.wrap(text, *codes)


def use_color(flag: str) -> bool:
    if flag == "always":
        return True
    if flag == "never":
        return False
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


# ---------------------------------------------------------------------------
# Link classification + extraction
#
# Absolute URLs are taken from anywhere, but only when the host looks real.
# Paths are taken from markup, CSS, JSON, and quoted strings. An unquoted
# "/..." is usually a JavaScript regex or a comment, so it is not a link.
# ---------------------------------------------------------------------------

_WEB_EXTS = (
    "php", "phtml", "asp", "aspx", "jsp", "jspx", "json", "js", "mjs", "cjs",
    "xml", "html", "htm", "xhtml", "cgi", "css", "scss", "less", "map",
    "png", "apng", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "bmp",
    "woff", "woff2", "ttf", "eot", "otf", "wasm", "txt", "pdf", "csv",
    "yml", "yaml", "vue", "jsx", "tsx", "ts", "mp4", "webm", "mp3", "webmanifest",
    "rss", "atom", "zip", "gz", "bak", "swf",
)
_WEAK_EXTS = {"do", "action", "pl"}
_EXT_RE = re.compile(
    r"(?i)\.(" + "|".join(_WEB_EXTS + tuple(sorted(_WEAK_EXTS))) + r")(?:[?#].*)?$"
)
_MIME_RE = re.compile(
    r"(?i)^(application|audio|font|example|image|message|model|multipart|text|video|chemical)/[a-z0-9!#$&^_.+-]+$"
)
_DATE_OR_FRACTION_RE = re.compile(r"^\d{1,4}(?:/\d{1,4})+$")
_OS_PATH_RE = re.compile(r"(?i)^/(?:dev|proc|sys|usr|bin|sbin|lib|lib64|tmp|home|root|etc)(?:/|$)")
_WIN_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")
_PATH_CHARS_RE = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@%/?#\-]+$")
_PREFIX_RE = re.compile(
    r"(?i)^(?:api|rest|ajax|endpoint|static|assets|uploads|public|wp-|graphql|\.well-known|v\d+)/"
)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~!$&'()*+,;=:@%-]{2,64}$")
# Dotted hosts, localhost, IPv4, and bracketed IPv6. Single-label names are
# allowed only on scheme URLs that also have a path or a port.
_HOST_CORE = r"localhost|(?:\d{1,3}\.){3}\d{1,3}|\[[0-9A-Fa-f:.]+\]|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"
_HOST_DOTTED = rf"(?:{_HOST_CORE})"
_HOST_ANY = rf"(?:{_HOST_CORE}|[A-Za-z0-9-]{{3,}})"
_TAIL = r"[^\s\"'<>`\\{|,]*"
_ABS_RE = re.compile(
    rf"(?i)(?<![A-Za-z0-9+.-])((?:https?|wss?)://(?:[^\s/?#@]+@)?{_HOST_ANY}(?::\d+)?{_TAIL})"
)
_PROTO_RE = re.compile(
    rf"(?i)(?<!:)(//{_HOST_DOTTED}(?::\d+)?{_TAIL})"
)
_QUOTED_RES = (
    re.compile(r"'((?:\\.|[^'\\\n]){1,4096})'"),
    re.compile(r'"((?:\\.|[^"\\\n]){1,4096})"'),
    re.compile(r"`((?:\\.|[^`\\]){1,4096})`", re.DOTALL),
)
_CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^)'\"]+)['\"]?\s*\)", re.IGNORECASE)
_CSS_IMPORT_RE = re.compile(r"@import\s+['\"]([^'\"]+)['\"]", re.IGNORECASE)
_SOURCEMAP_RE = re.compile(r"(?i)(?:sourceMappingURL|sourceURL)\s*=\s*(\S+)")
_WWW_RE = re.compile(r"(?i)^www\.(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:/[^\s]*)?$")
_JS_ESCAPES = {
    "23": "#",
    "25": "%",
    "26": "&",
    "2b": "+",
    "2f": "/",
    "3a": ":",
    "3d": "=",
    "3f": "?",
    "40": "@",
}
_NAMESPACE_SUFFIXES = (
    "w3.org",
    "json-schema.org",
    "schemas.xmlsoap.org",
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "purl.org",
    "ns.adobe.com",
    "xmlns.jcp.org",
    "xmlsoap.org",
)
_STOP_SEGMENTS = frozenset(
    {
        "a", "b", "br", "button", "div", "else", "f", "false", "footer", "for",
        "form", "function", "g", "gi", "gm", "h1", "h2", "h3", "head", "header",
        "hr", "html", "i", "if", "ig", "img", "input", "instanceof", "let", "li",
        "link", "m", "main", "meta", "n", "nan", "nav", "new", "null", "p", "path",
        "r", "return", "s", "script", "section", "span", "style", "svg", "t",
        "table", "td", "th", "this", "tr", "true", "typeof", "u", "ul", "undefined",
        "use", "var", "while", "y",
    }
)
_SINGLE_HOST_STOP = frozenset(
    {"about", "blob", "com", "data", "file", "http", "https", "javascript", "mailto", "net", "org", "src", "url", "www"}
)
_TRAIL_CHARS = set(".,;:!?\"'`<>]}|$")
_LAX_ATTRS = {"href", "src", "action", "formaction", "poster", "cite", "icon", "manifest", "longdesc", "data"}
_URL_ATTRS = _LAX_ATTRS | {
    "ping", "srcset", "imagesrcset", "data-src", "data-href", "data-url", "data-endpoint",
    "data-api", "data-srcset", "data-background", "data-original", "data-poster",
    "data-lazy", "data-image", "data-full", "data-hi-res",
}
_SRCSET_ATTRS = {"srcset", "imagesrcset", "data-srcset"}

LINK_HEADER_RE = re.compile(r"<([^>]+)>")

def classify_link(link: str) -> str:
    low = link.lower()
    if low.startswith("https://"):
        return "https"
    if low.startswith("http://"):
        return "http"
    if low.startswith("wss://"):
        return "wss"
    if low.startswith("ws://"):
        return "ws"
    if low.startswith("//"):
        return "protocol-relative"
    if low.startswith("www.") and "." in low[4:]:
        return "https"
    if low.startswith("data:"):
        return "data"
    if low.startswith("mailto:"):
        return "mailto"
    if low.startswith("/"):
        return "absolute-path"
    if re.search(r"(?:api|graphql|ajax|endpoint|v\d+)/", low) or low.endswith(
        (".js", ".mjs", ".cjs", ".json", ".php", ".aspx", ".jsp", ".cgi")
    ):
        return "js-endpoint"
    return "relative-path"


def unescape_js_urls(text: str) -> str:
    """Turn the slash escapes JS uses inside strings into real slashes."""

    def repl(match: re.Match[str]) -> str:
        return _JS_ESCAPES.get(match.group(1).lower(), match.group(0))

    text = re.sub(r"\\u00([0-9a-fA-F]{2})", repl, text)
    text = re.sub(r"\\x([0-9a-fA-F]{2})", repl, text)
    return text.replace("\\/", "/")


def _decode_entities(value: str) -> str:
    value = re.sub(r"(?i)&#x2f;?", "/", value)
    return (
        value.replace("&#47;", "/")
        .replace("&sol;", "/")
        .replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&#34;", '"')
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
    )


def _trim_tail(value: str) -> str:
    if "${" in value:
        value = value.split("${", 1)[0]
    if value.endswith("*/"):
        value = value[:-2]
    changed = True
    while value and changed:
        changed = False
        if value[-1] in _TRAIL_CHARS:
            value = value[:-1]
            changed = True
        elif value.endswith(")") and value.count("(") < value.count(")"):
            value = value[:-1]
            changed = True
        elif value.endswith("*") and not value.endswith("/*"):
            value = value[:-1]
            changed = True
    return value


def _namespace_host(host: str) -> bool:
    return any(host == suffix or host.endswith("." + suffix) for suffix in _NAMESPACE_SUFFIXES)


def _host_ok(link: str, *, allow_single: bool) -> bool:
    parsed = urlparse(link if "://" in link else "http:" + link)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or _namespace_host(host):
        return False
    if host == "localhost":
        return True
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in host.split("."))
    if ":" in host:
        return re.fullmatch(r"[0-9a-f:.]+", host) is not None
    if "." in host:
        tld = host.rsplit(".", 1)[-1]
        return tld.isalpha() and len(tld) >= 2
    if not allow_single or host in _SINGLE_HOST_STOP or len(host) < 3:
        return False
    return bool(parsed.path) or parsed.port is not None


def _extension(link: str) -> str | None:
    match = _EXT_RE.search(link)
    return match.group(1).lower() if match else None


def _path_ok(link: str, trust: str) -> bool:
    if _WIN_PATH_RE.match(link) or _DATE_OR_FRACTION_RE.match(link) or _MIME_RE.match(link):
        return False
    if not _PATH_CHARS_RE.match(link):
        return False
    if link.startswith(("#",)):
        return False
    if link.startswith("?"):
        return trust in {"attribute", "lax"} and len(link) > 1
    ext = _extension(link)
    if ext in _WEAK_EXTS and "/" not in link:
        return False
    if _OS_PATH_RE.match(link) and ext is None:
        return False
    if link.startswith(("http://", "https://", "ws://", "wss://", "//")):
        return False
    # "0;url=https://host/x" is a wrapper around a URL the absolute pass
    # already kept. A real path may still carry an absolute URL in its query.
    if "://" in link and not link.startswith(("/", "./", "../")):
        head = link.split("://", 1)[0]
        if "?" not in head and "#" not in head:
            return False
    segments = [part for part in link.split("/") if part not in {"", ".", ".."}]
    if link.startswith(("/", "./", "../")):
        if ext or "?" in link:
            return True
        if not segments:
            return False
        if len(segments) == 1:
            label = segments[0].lower()
            return label not in _STOP_SEGMENTS and len(label) >= 3
        if segments[-1].lower() in _STOP_SEGMENTS and re.fullmatch(r"[gimsuy]{1,4}", segments[-1].lower()):
            return trust in {"attribute", "lax"}
        return True
    if ext:
        return True
    if _PREFIX_RE.match(link):
        return True
    if link.count("/") >= 2:
        return True
    if trust == "lax" and _TOKEN_RE.match(link) and not link.isdigit() and link.lower() not in _STOP_SEGMENTS:
        return True
    return False


def keep_link(raw: str, *, trust: str = "quoted") -> str | None:
    """Return a normalized link, or None when `raw` is not one.

    `url` keeps scheme and protocol-relative URLs with a real host.
    `quoted` also keeps paths from strings and JSON.
    `attribute` is that, plus query-only hrefs.
    `lax` is for href/src, where a bare relative token is still a link.
    """
    value = unescape_js_urls(raw.strip())
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"`":
        value = value[1:-1].strip()
    value = _decode_entities(value)
    for stopper in ('"', "'", "<", ">", "\n", "\r", "\t"):
        if stopper in value:
            value = value.split(stopper, 1)[0]
    value = value.strip()
    value = re.sub(r"(?i)^(?:url\s*=\s*)+", "", value)
    value = _trim_tail(value).strip()
    if not value or len(value) > 2048 or len(value) < 2:
        return None
    if any(ord(ch) < 32 for ch in value):
        return None
    if any(ch.isspace() for ch in value):
        return None
    low = value.lower()
    if low.startswith(("javascript:", "data:", "blob:", "about:", "file:", "chrome:", "chrome-extension:", "view-source:")):
        return None
    if low.startswith(("https://", "http://", "wss://", "ws://")):
        return value if _host_ok(value, allow_single=True) else None
    if low.startswith("//"):
        return value if _host_ok(value, allow_single=False) else None
    if low.startswith("mailto:"):
        return value if "@" in value[7:] else None
    if trust == "url":
        return None
    if _WWW_RE.match(value):
        return value
    if _path_ok(value, trust):
        return value
    return None


def _remember(results: list[tuple[str, str, str]], seen: set[str], link: str, origin: str) -> None:
    if link in seen:
        return
    seen.add(link)
    results.append((link, classify_link(link), origin))


def _add_raw(results: list[tuple[str, str, str]], seen: set[str], raw: str, origin: str, trust: str) -> None:
    kept = keep_link(raw, trust=trust)
    extras: list[tuple[str, str]] = []
    if kept:
        extras.append((kept, origin))
        try:
            decoded = unquote(kept)
        except Exception:
            decoded = kept
        if decoded != kept:
            decoded_kept = keep_link(decoded, trust=trust)
            if decoded_kept and decoded_kept != kept:
                extras.append((decoded_kept, origin + "+decoded"))
    else:
        try:
            decoded = unquote(raw)
        except Exception:
            decoded = raw
        if decoded != raw:
            decoded_kept = keep_link(decoded, trust=trust)
            if decoded_kept:
                extras.append((decoded_kept, origin + "+decoded"))
    for link, org in extras:
        _remember(results, seen, link, org)


def _split_srcset(value: str) -> list[str]:
    tokens: list[str] = []
    for piece in value.split(","):
        piece = piece.strip()
        if not piece:
            continue
        tokens.append(piece.split()[0])
    return tokens


class _HTMLLinks(HTMLParser):
    def __init__(self, add) -> None:
        super().__init__(convert_charrefs=True)
        self._add = add

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if not value:
                continue
            attr = name.lower().split(":")[-1]
            full = name.lower()
            if full in _SRCSET_ATTRS or attr in _SRCSET_ATTRS:
                for token in _split_srcset(value):
                    self._add(token, "html", "attribute")
                continue
            if attr == "content":
                match = re.search(r"(?i)\burl\s*=\s*(\S+)", value)
                if match:
                    self._add(match.group(1), "html", "attribute")
                else:
                    self._add(value, "html", "quoted")
                continue
            if attr == "ping":
                for token in value.split():
                    self._add(token, "html", "attribute")
                continue
            if full in _URL_ATTRS or attr in _URL_ATTRS:
                trust = "lax" if attr in _LAX_ATTRS or full in _LAX_ATTRS else "attribute"
                self._add(value, "html", trust)
                continue
            if full.startswith("data-"):
                self._add(value, "html", "attribute")

    def error(self, message: str) -> None:
        return


def _harvest_html(text: str, add) -> None:
    if "<" not in text or ">" not in text:
        return
    parser = _HTMLLinks(add)
    try:
        parser.feed(text)
        parser.close()
    except Exception:
        return


def walk_json(obj, add) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(key, str):
                add(key, "json", "quoted")
            walk_json(value, add)
    elif isinstance(obj, list):
        for item in obj:
            walk_json(item, add)
    elif isinstance(obj, str):
        add(obj, "json", "quoted")


def extract_from_text(text: str, source: str = "body") -> list[tuple[str, str, str]]:
    """Return (link, kind, origin) for links in a body.

    `source` is accepted for callers that label a buffer; origins stay
    html, css, json, and regex.

    The buffer is not unescaped up front. Doing that turns a regex literal
    such as `/foo\\/bar/g` into a path. `keep_link` unescapes each candidate
    after it is taken from quotes, markup, CSS, or JSON.
    """
    del source
    results: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    def add(raw: str, origin: str, trust: str = "quoted") -> None:
        _add_raw(results, seen, raw, origin, trust)

    _harvest_html(text, add)
    for match in _CSS_URL_RE.finditer(text):
        add(match.group(1), "css", "attribute")
    for match in _CSS_IMPORT_RE.finditer(text):
        add(match.group(1), "css", "attribute")
    for match in _SOURCEMAP_RE.finditer(text):
        add(match.group(1), "regex", "quoted")
    if text.lstrip().startswith(("{", "[")):
        try:
            walk_json(json.loads(text), add)
        except Exception:
            pass
    for match in _ABS_RE.finditer(text):
        add(match.group(1), "regex", "url")
    for match in _PROTO_RE.finditer(text):
        add(match.group(1), "regex", "url")
    for pattern in _QUOTED_RES:
        for match in pattern.finditer(text):
            add(match.group(1), "regex", "quoted")
    return results


# ---------------------------------------------------------------------------
# Input loaders
# ---------------------------------------------------------------------------

def sniff_kind(path: str, head: bytes) -> str:
    name = path.lower()
    if name.endswith((".har", ".zhar")):
        return "har"
    if name.endswith((".mitm", ".flow", ".flows", ".dump")):
        return "mitm"
    stripped = head.lstrip()
    if stripped.startswith(b"{") and b'"log"' in stripped[:4000]:
        return "har"
    if stripped.startswith((b"HTTP/", b"http/")):
        return "raw-http"
    # mitmproxy tnetstring dumps are binary; they typically do not start with '{'
    if b"\x00" in head[:64] or head[:1] not in b"{[<#!HGgh\t\n\r ":
        return "mitm"
    return "text"


def split_raw_http(data: str) -> tuple[dict[str, str], str]:
    header_blob, _, body = data.partition("\r\n\r\n")
    if body == "" and "\n\n" in data:
        header_blob, _, body = data.partition("\n\n")
    headers: dict[str, str] = {}
    for line in header_blob.splitlines()[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers, body


_BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".webm", ".mp3",
    ".wav", ".pdf", ".zip", ".gz", ".tgz", ".wasm",
}


def scannable_mime(content_type: str | None) -> bool:
    """False for image, font, audio, and video bodies. SVG stays scannable."""
    if not content_type:
        return True
    ctype = content_type.split(";", 1)[0].strip().lower()
    if not ctype or ctype.startswith("text/"):
        return True
    if any(bit in ctype for bit in ("svg", "json", "javascript", "ecmascript", "xml", "html", "css", "yaml")):
        return True
    if ctype.startswith(("image/", "audio/", "video/", "font/")):
        return False
    if ctype in {
        "application/octet-stream",
        "application/pdf",
        "application/zip",
        "application/gzip",
        "application/wasm",
        "application/x-protobuf",
    }:
        return False
    return True


def _kept_header(raw: str) -> str | None:
    return keep_link(raw, trust="attribute")


def extract_from_headers(headers: dict[str, str]) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        cleaned = _kept_header(raw)
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            found.append((cleaned, classify_link(cleaned), "header"))

    for key in ("location", "content-location", "x-redirect"):
        val = headers.get(key)
        if val:
            add(val)
    link_h = headers.get("link")
    if link_h:
        for match in LINK_HEADER_RE.finditer(link_h):
            add(match.group(1))
    refresh = headers.get("refresh")
    if refresh:
        add(refresh.split(";", 1)[-1].strip())
    return found


def load_text_file(path: str) -> list[dict]:
    raw_bytes = read_bytes(path)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = raw_bytes.decode("latin-1", errors="replace")

    kind = sniff_kind(path, raw_bytes[:4096])
    records: list[dict] = []

    if kind == "raw-http":
        headers, body = split_raw_http(text)
        ctype = headers.get("content-type", "")
        links = extract_from_headers(headers)
        if scannable_mime(ctype):
            links.extend(extract_from_text(body))
        records.append(
            {
                "source": path,
                "url": headers.get("x-request-url") or path,
                "status": text.split(None, 2)[1] if text.startswith("HTTP/") else None,
                "content_type": headers.get("content-type", ""),
                "links": links,
            }
        )
        return records

    if kind == "har":
        har_records = load_har_bytes(raw_bytes, path)
        if har_records is not None:
            return har_records

    suffix = os.path.splitext(path)[1].lower()
    links = [] if suffix in _BINARY_SUFFIXES else extract_from_text(text)
    records.append(
        {
            "source": path,
            "url": path,
            "status": None,
            "content_type": "",
            "links": links,
        }
    )
    return records


def _har_entries(data: object) -> list | None:
    """Return HAR entries, or None when this JSON is not a HAR log."""
    if not isinstance(data, dict):
        return None
    log = data.get("log")
    if not isinstance(log, dict):
        return None
    entries = log.get("entries")
    if not isinstance(entries, list):
        return None
    if entries and not any(isinstance(entry, dict) for entry in entries):
        return None
    return entries


def load_har_bytes(raw_bytes: bytes, path: str) -> list[dict] | None:
    """Parse a HAR document. None means these bytes are not a HAR log."""
    text = raw_bytes.decode("utf-8", errors="replace")
    try:
        data = json.loads(text)
    except Exception:
        return None
    entries = _har_entries(data)
    if entries is None:
        return None
    records: list[dict] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        req_url = request.get("url", "")
        content = response.get("content") if isinstance(response.get("content"), dict) else {}
        body = content.get("text") or ""
        if content.get("encoding") == "base64" and body:
            import base64

            try:
                body = base64.b64decode(body).decode("utf-8", errors="replace")
            except Exception:
                body = ""
        headers = {}
        for header in response.get("headers") or []:
            if isinstance(header, dict):
                headers[(header.get("name") or "").lower()] = header.get("value") or ""
        links: list[tuple[str, str, str]] = []
        if req_url:
            cleaned = keep_link(req_url, trust="url")
            if cleaned:
                links.append((cleaned, classify_link(cleaned), "request"))
        links.extend(extract_from_headers(headers))
        mime = content.get("mimeType") or headers.get("content-type", "")
        if body and scannable_mime(mime):
            links.extend(extract_from_text(body))
        records.append(
            {
                "source": path,
                "url": req_url,
                "status": response.get("status"),
                "content_type": (content.get("mimeType") or headers.get("content-type", "")),
                "links": links,
            }
        )
    return records


def load_mitm_file(path: str) -> list[dict]:
    try:
        from mitmproxy import http, io
        from mitmproxy.exceptions import FlowReadException
    except ImportError as exc:
        raise RuntimeError(
            "This looks like a mitmproxy flow dump. Install mitmproxy to parse it:\n"
            "    pip install mitmproxy\n"
            "Alternatively export the response as HAR or raw_response and re-run."
        ) from exc

    records: list[dict] = []
    with open(path, "rb") as handle:
        reader = io.FlowReader(handle)
        try:
            for flow in reader.stream():
                if not isinstance(flow, http.HTTPFlow):
                    continue
                req_url = ""
                try:
                    req_url = flow.request.pretty_url
                except Exception:
                    req_url = getattr(flow.request, "url", "") or ""

                links: list[tuple[str, str, str]] = []
                if req_url:
                    cleaned = keep_link(req_url, trust="url")
                    if cleaned:
                        links.append((cleaned, classify_link(cleaned), "request"))

                headers: dict[str, str] = {}
                body = ""
                status = None
                ctype = ""
                if flow.response is not None:
                    status = flow.response.status_code
                    try:
                        headers = {k.lower(): v for k, v in flow.response.headers.items()}
                    except Exception:
                        headers = {}
                    ctype = headers.get("content-type", "")
                    links.extend(extract_from_headers(headers))
                    try:
                        body = flow.response.get_text(strict=False) or ""
                    except Exception:
                        raw = flow.response.content or b""
                        body = raw.decode("utf-8", errors="replace")
                    if body and scannable_mime(ctype):
                        links.extend(extract_from_text(body))

                records.append(
                    {
                        "source": path,
                        "url": req_url,
                        "status": status,
                        "content_type": ctype,
                        "links": links,
                    }
                )
        except FlowReadException as exc:
            raise RuntimeError(f"Flow file could not be read: {exc}") from exc
    return records


def read_bytes(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as handle:
        return handle.read()


def load_input(path: str) -> list[dict]:
    if path == "-":
        data = sys.stdin.buffer.read()
        kind = sniff_kind("-", data[:4096])
        tmp = io.BytesIO(data)
        if kind == "har":
            har_records = load_har_bytes(data, "-")
            if har_records is not None:
                return har_records
        if kind == "mitm":
            raise RuntimeError("Reading mitmproxy dumps from stdin is not supported; pass a file path.")
        text = data.decode("utf-8", errors="replace")
        if kind == "raw-http":
            headers, body = split_raw_http(text)
            ctype = headers.get("content-type", "")
            links = extract_from_headers(headers)
            if scannable_mime(ctype):
                links.extend(extract_from_text(body))
            return [{"source": "-", "url": "-", "status": None, "content_type": ctype, "links": links}]
        return [{"source": "-", "url": "-", "status": None, "content_type": "", "links": extract_from_text(text)}]

    if os.path.splitext(path)[1].lower() in _BINARY_SUFFIXES:
        return [{"source": path, "url": path, "status": None, "content_type": "", "links": []}]
    head = b""
    with open(path, "rb") as handle:
        head = handle.read(4096)
    kind = sniff_kind(path, head)
    if kind == "mitm":
        return load_mitm_file(path)
    if kind == "har":
        har_records = load_har_bytes(read_bytes(path), path)
        if har_records is not None:
            return har_records
    return load_text_file(path)


# ---------------------------------------------------------------------------
# Filtering / output
# ---------------------------------------------------------------------------

def flatten(records: list[dict], include_requests: bool) -> list[dict]:
    rows: list[dict] = []
    for rec in records:
        base = rec.get("url") or ""
        for link, kind, origin in rec.get("links", []):
            if origin == "request" and not include_requests:
                continue
            resolved = try_resolve(link, base)
            rows.append(
                {
                    "link": link,
                    "resolved": resolved,
                    "kind": kind,
                    "origin": origin,
                    "flow_url": base,
                    "status": rec.get("status"),
                    "content_type": rec.get("content_type") or "",
                    "source": rec.get("source") or "",
                }
            )
    return rows


def try_resolve(link: str, base: str) -> str:
    if _WWW_RE.match(link):
        return "https://" + link
    if not base or not base.startswith(("http://", "https://")):
        return link
    if link.startswith(("http://", "https://", "ws://", "wss://", "mailto:", "data:")):
        return link
    try:
        if link.startswith("//"):
            return urlparse(base).scheme + ":" + link
        return urljoin(base, link)
    except Exception:
        return link


def apply_filters(rows: list[dict], args: argparse.Namespace) -> list[dict]:
    out = rows
    if args.kind:
        wanted = {k.strip().lower() for k in args.kind.split(",")}
        out = [r for r in out if r["kind"] in wanted]
    if args.origin:
        wanted = {k.strip().lower() for k in args.origin.split(",")}
        out = [r for r in out if r["origin"].split("+", 1)[0] in wanted]
    if args.contains:
        needle = args.contains.lower()
        out = [r for r in out if needle in r["link"].lower() or needle in r["resolved"].lower()]
    if args.regex:
        pattern = re.compile(args.regex, re.IGNORECASE)
        out = [r for r in out if pattern.search(r["link"]) or pattern.search(r["resolved"])]
    if args.domain:
        domains = {d.strip().lower().lstrip(".") for d in args.domain.split(",") if d.strip()}
        filtered = []
        for row in out:
            host = urlparse(row["resolved"] if "://" in row["resolved"] else row["link"]).hostname or ""
            host = host.lower()
            if any(host == d or host.endswith("." + d) for d in domains):
                filtered.append(row)
        out = filtered
    if args.unique:
        seen: set[str] = set()
        uniq = []
        keyname = "resolved" if args.resolve else "link"
        for row in out:
            key = row[keyname]
            if key not in seen:
                seen.add(key)
                uniq.append(row)
        out = uniq
    if args.sort:
        keyname = "resolved" if args.resolve else "link"
        out = sorted(out, key=lambda r: (r["kind"], r[keyname].lower()))
    return out


def print_rows(rows: list[dict], args: argparse.Namespace, pal: Palette) -> None:
    if not rows:
        print(pal.warn("No links found."))
        return

    counts = Counter(r["kind"] for r in rows)
    print(pal.title("┌─ flowcarve"))
    print(pal.dim(f"│  {len(rows)} link(s)  •  kinds: " + ", ".join(f"{k}={v}" for k, v in counts.most_common())))
    print(pal.title("└" + "─" * 42))
    print()

    if args.group:
        groups: OrderedDict[str, list[dict]] = OrderedDict()
        for row in rows:
            groups.setdefault(row["kind"], []).append(row)
        for kind, group in groups.items():
            label = f"[{kind}] {len(group)}"
            print(pal.kind(kind, label))
            print(pal.dim("─" * max(24, len(label))))
            for row in group:
                print_one(row, args, pal)
            print()
    else:
        for row in rows:
            print_one(row, args, pal)

    print()
    print(pal.ok(f"Done. {len(rows)} link(s)."))


def print_one(row: dict, args: argparse.Namespace, pal: Palette) -> None:
    display = row["resolved"] if args.resolve else row["link"]
    kind_tag = pal.kind(row["kind"], f"{row['kind']:<18}")
    origin_tag = pal.dim(f"{row['origin']:<14}")
    extra = ""
    if args.verbose:
        bits = []
        if row.get("flow_url"):
            bits.append(row["flow_url"])
        if row.get("status") is not None:
            bits.append(str(row["status"]))
        extra = pal.dim("  :: " + " · ".join(bits)) if bits else ""
    print(f"  {kind_tag} {origin_tag} {pal.kind(row['kind'], display)}{extra}")


def save_rows(rows: list[dict], path: str, fmt: str, resolve: bool) -> None:
    field = "resolved" if resolve else "link"
    if fmt == "txt":
        with open(path, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(row[field] + "\n")
    elif fmt == "json":
        payload = rows
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
    elif fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=["link", "resolved", "kind", "origin", "flow_url", "status", "content_type", "source"],
            )
            writer.writeheader()
            writer.writerows(rows)
    else:
        raise ValueError(f"Unknown format: {fmt}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flowcarve",
        description="Carve links out of mitmproxy dumps, HAR files, and raw HTTP responses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Supported inputs
  • mitmproxy flow dumps   (.mitm / whatever mitmdump -w wrote)  [needs: pip install mitmproxy]
  • HAR exports            (.har)
  • raw HTTP responses     (export.file raw_response)
  • plain HTML / JS / JSON / text
  • stdin                  (pipe a body or HAR)

Examples
  python3 flowcarve.py flows.mitm --unique --sort
  python3 flowcarve.py response.txt --save links.txt
  python3 flowcarve.py capture.har -o urls.json --format json --include-requests
  python3 flowcarve.py dump.mitm --kind https,absolute-path --group
        """,
    )
    parser.add_argument("inputs", nargs="+", help="Input file(s), or - for stdin")
    parser.add_argument("-o", "--save", "--output", dest="save", metavar="FILE", help="Write results to FILE")
    parser.add_argument(
        "--format",
        choices=("txt", "json", "csv"),
        default=None,
        help="Output file format (default: infer from extension, else txt)",
    )
    parser.add_argument("--include-requests", action="store_true", help="Also keep the request URLs from each flow")
    parser.add_argument("--unique", action="store_true", help="Deduplicate links")
    parser.add_argument("--sort", action="store_true", help="Sort by kind then URL")
    parser.add_argument("--group", action="store_true", help="Group colored output by link kind")
    parser.add_argument("--resolve", action="store_true", help="Resolve relative links against the flow request URL")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show the flow URL / status next to each link")
    parser.add_argument("--kind", help="Only these kinds (comma-separated): https,http,wss,ws,protocol-relative,absolute-path,relative-path,js-endpoint,mailto")
    parser.add_argument("--origin", help="Only these origins (comma-separated): request,header,html,css,json,regex")
    parser.add_argument("--contains", help="Keep links containing this substring")
    parser.add_argument("--regex", help="Keep links matching this regex")
    parser.add_argument("--domain", help="Keep links whose host matches this domain (comma-separated)")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="Color output (default: auto)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Do not print links to stdout (useful with --save)")
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def infer_format(path: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    low = path.lower()
    if low.endswith(".json"):
        return "json"
    if low.endswith(".csv"):
        return "csv"
    return "txt"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    pal = Palette(use_color(args.color) and not args.quiet)

    records: list[dict] = []
    errors = 0
    for path in args.inputs:
        if path != "-" and not os.path.exists(path):
            print(pal.err(f"Not found: {path}"), file=sys.stderr)
            errors += 1
            continue
        try:
            records.extend(load_input(path))
        except Exception as exc:
            print(pal.err(f"Failed to read {path}: {exc}"), file=sys.stderr)
            errors += 1

    rows = apply_filters(flatten(records, args.include_requests), args)

    if not args.quiet:
        print_rows(rows, args, pal)

    if args.save:
        fmt = infer_format(args.save, args.format)
        save_rows(rows, args.save, fmt, args.resolve)
        if not args.quiet:
            print(pal.ok(f"Wrote {len(rows)} link(s) to {args.save} ({fmt})"))

    return 1 if errors and not rows else 0


if __name__ == "__main__":
    sys.exit(main())
