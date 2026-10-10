#!/usr/bin/env python3
"""Skiff: multi-threaded HTTP fuzzer.

Replace the FUZZ placeholder with words from a wordlist. Results go to
stdout. Progress, warnings, and the banner go to stderr.
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import random
import re
import sys
import threading
import time
import urllib3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator
from urllib.parse import quote, urlparse

import requests
from colorama import Fore, Style

VERSION = "2.0.0"
PLACEHOLDER = "FUZZ"
DEFAULT_USER_AGENT = f"Skiff v{VERSION}"
# Combo mode builds one request per tuple. Refuse accidental explosions.
MAX_COMBO_REQUESTS = 2_000_000
HOP_HEADERS = {
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "upgrade",
    "te",
    "trailer",
    "host",
}

# Mast sits on column 25 so the sail, spar, and hull share one centerline.
SKIFF_BOAT = r"""
                         .
                        /|\
                       / | \
                      /  |  \
                     /   |   \
               _____/____|____\_____
            __|                     |__
       ~~~~|                          |~~~~
          '~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
             ~      ~      ~      ~
""".strip("\n")

# Five-high glyphs. Two F letters share a shape and take different colors.
WORDMARK = (
    ("  ____  ", " / ___| ", " \\___ \\ ", "  ___) |", " |____/ "),
    (" _  __  ", "| |/ /  ", "| ' /   ", "| . \\   ", "|_|\\_\\  "),
    (" ___ ", "|_ _|", " | | ", " | | ", "|___|"),
    (" _____  ", "|  ___| ", "| |_    ", "|  _|   ", "|_|     "),
    (" _____  ", "|  ___| ", "| |_    ", "|  _|   ", "|_|     "),
)
WORDMARK_COLORS = (
    Fore.CYAN + Style.BRIGHT,
    Fore.GREEN + Style.BRIGHT,
    Fore.YELLOW + Style.BRIGHT,
    Fore.MAGENTA + Style.BRIGHT,
    Fore.RED + Style.BRIGHT,
)


def die(message: str, code: int = 1) -> None:
    """Print an error to stderr and exit."""
    sys.stderr.write(f"[!] {message}\n")
    raise SystemExit(code)


# --- terminal output -------------------------------------------------------

class Colors:
    """ANSI colors that stay off unless color is enabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, style: str) -> str:
        if not self.enabled or not style:
            return text
        return f"{style}{text}{Style.RESET_ALL}"

    def status(self, code: int) -> str:
        if 200 <= code < 300:
            style = Fore.GREEN + Style.BRIGHT
        elif 300 <= code < 400:
            style = Fore.CYAN + Style.BRIGHT
        elif 400 <= code < 500:
            style = Fore.YELLOW + Style.BRIGHT
        elif 500 <= code < 600:
            style = Fore.RED + Style.BRIGHT
        else:
            style = Fore.MAGENTA + Style.BRIGHT
        return self.paint(str(code), style)

    def payload(self, text: str) -> str:
        return self.paint(text, Fore.MAGENTA + Style.BRIGHT)


def resolve_color(args: argparse.Namespace) -> bool:
    """Honor --color, --no-color, NO_COLOR, and whether stdout is a terminal."""
    if args.no_color:
        return False
    if args.color:
        return True
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _paint_chars(line: str, colors: Colors, style_for) -> str:
    return "".join(ch if ch == " " else colors.paint(ch, style_for(index, ch)) for index, ch in enumerate(line))


def _sail_style(_index: int, char: str) -> str:
    if char in ".|":
        return Fore.YELLOW + Style.BRIGHT
    if char == "/":
        return Fore.WHITE + Style.BRIGHT
    if char == "\\":
        return Fore.CYAN + Style.BRIGHT
    return Fore.WHITE + Style.BRIGHT


def _hull_style(deck: bool):
    def style(index: int, char: str) -> str:
        if char == "|":
            return Fore.YELLOW + Style.BRIGHT
        if char == "~":
            return (Fore.CYAN if index % 2 == 0 else Fore.BLUE) + Style.BRIGHT
        if deck:
            return Fore.WHITE + Style.BRIGHT
        return Fore.CYAN + Style.BRIGHT

    return style


def _water_style(index: int, _char: str) -> str:
    if index % 2 == 0:
        return Fore.BLUE + Style.BRIGHT
    return Fore.CYAN + Style.BRIGHT


def render_boat(colors: Colors) -> str:
    """Color the sailing skiff: yellow mast, white and cyan sails, blue water."""
    painted: list[str] = []
    for index, line in enumerate(SKIFF_BOAT.splitlines()):
        if index <= 4:
            painted.append(_paint_chars(line, colors, _sail_style))
        elif index == 5:
            painted.append(_paint_chars(line, colors, _hull_style(True)))
        elif index <= 7:
            painted.append(_paint_chars(line, colors, _hull_style(False)))
        else:
            painted.append(_paint_chars(line, colors, _water_style))
    return "\n".join(painted)


def render_wordmark(colors: Colors) -> str:
    """Paint S, K, I, F, F in cyan, green, yellow, magenta, and red."""
    rows: list[str] = []
    for row in range(len(WORDMARK[0])):
        rows.append(" ".join(colors.paint(glyph[row], style) for glyph, style in zip(WORDMARK, WORDMARK_COLORS)))
    rows.append(colors.paint(f"Skiff v{VERSION}", Fore.WHITE + Style.BRIGHT))
    rows.append(colors.paint("a small boat for a wide search", Fore.BLUE + Style.BRIGHT))
    return "\n".join(rows)


def render_banner(colors: Colors) -> str:
    return render_boat(colors) + "\n\n" + render_wordmark(colors) + "\n"


class Console:
    """Locked stdout/stderr writer. Progress is a single stderr line."""

    def __init__(self, colors: Colors, silent: bool) -> None:
        self.colors = colors
        self.silent = silent
        self.lock = threading.RLock()

    def _stderr_tty(self) -> bool:
        try:
            return sys.stderr.isatty()
        except Exception:
            return False

    def _write_stderr(self, text: str) -> None:
        if self._stderr_tty():
            sys.stderr.write("\r\033[K")
        sys.stderr.write(text)
        if not text.endswith("\n"):
            sys.stderr.write("\n")
        sys.stderr.flush()

    def banner(self) -> None:
        if self.silent:
            return
        art = render_banner(self.colors)
        with self.lock:
            sys.stderr.write(art)
            sys.stderr.flush()

    def info(self, message: str) -> None:
        if self.silent:
            return
        with self.lock:
            self._write_stderr(self.colors.paint(message, Fore.CYAN))

    def warn(self, message: str) -> None:
        if self.silent:
            return
        with self.lock:
            self._write_stderr(self.colors.paint(message, Fore.YELLOW))

    def error(self, message: str) -> None:
        """Errors stay visible in silent mode so a failed scan is not invisible."""
        with self.lock:
            self._write_stderr(self.colors.paint(message, Fore.RED))

    def hit(self, line: str) -> None:
        with self.lock:
            if self._stderr_tty():
                sys.stderr.write("\r\033[K")
                sys.stderr.flush()
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def progress(self, message: str) -> None:
        if self.silent or not self._stderr_tty():
            return
        painted = self.colors.paint(message, Fore.BLUE)
        with self.lock:
            sys.stderr.write("\r" + painted + "\033[K")
            sys.stderr.flush()

    def clear_progress(self) -> None:
        if self.silent or not self._stderr_tty():
            return
        with self.lock:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()


# --- command line ----------------------------------------------------------

def parse_int_set(text: str, flag: str) -> set[int]:
    values: set[int] = set()
    for part in text.split(","):
        piece = part.strip()
        if not piece:
            continue
        try:
            number = int(piece)
        except ValueError:
            die(f"{flag} expects integers, got {piece!r}")
        if number < 0:
            die(f"{flag} cannot be negative ({number})")
        values.add(number)
    if not values:
        die(f"{flag} needs at least one integer")
    return values


def parse_header_pair(text: str, flag: str) -> tuple[str, str]:
    if ":" not in text:
        die(f"{flag} expects Key: Value, got {text!r}")
    key, value = text.split(":", 1)
    key = key.strip()
    value = value.strip()
    if not key:
        die(f"{flag} header name is empty in {text!r}")
    return key, value


def parse_cookie_string(text: str) -> list[tuple[str, str]]:
    cookies: list[tuple[str, str]] = []
    for part in text.split(";"):
        piece = part.strip()
        if not piece:
            continue
        if "=" not in piece:
            die(f"cookie {piece!r} is missing '=' (expected key=value)")
        key, value = piece.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            die(f"cookie name is empty in {text!r}")
        cookies.append((key, value))
    if not cookies:
        die(f"could not parse cookies from {text!r}")
    return cookies


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skiff.py",
        description=(
            "Skiff v%s — HTTP fuzzer. Put FUZZ where each word should be "
            "injected." % VERSION
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"Skiff {VERSION}")
    parser.add_argument("-u", "--url", help="Target URL. Use FUZZ as the injection point.")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist path, or - to read stdin.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent workers.")
    parser.add_argument(
        "-m", "--method",
        default=None,
        help="HTTP method. Default GET, or POST when --data is set. Ignored with --request-file.",
    )
    parser.add_argument("-d", "--data", help="Request body. May contain FUZZ.")
    parser.add_argument("-fc", "--filter-code", help="Hide these status codes. Example: 404,500")
    parser.add_argument("-mc", "--match-code", help="Show only these status codes. Example: 200,301,302")
    parser.add_argument("-fs", "--filter-size", help="Hide these body sizes in bytes. 0 is allowed.")
    parser.add_argument("-ms", "--match-size", help="Show only these body sizes in bytes.")
    parser.add_argument("-fw", "--filter-words", help="Hide responses with these word counts.")
    parser.add_argument("-mw", "--match-words", help="Show only responses with these word counts.")
    parser.add_argument("-fl", "--filter-lines", help="Hide responses with these line counts.")
    parser.add_argument("-ml", "--match-lines", help="Show only responses with these line counts.")
    parser.add_argument("--match-regex", help="Show responses whose body matches this regex.")
    parser.add_argument("--filter-regex", help="Hide responses whose body matches this regex.")
    parser.add_argument(
        "--match-header",
        action="append",
        help="Require this response header (repeatable, all must match). Example: Content-Type:text/html",
    )
    parser.add_argument("-o", "--output", help="Write hits to this file as well as stdout.")
    parser.add_argument(
        "-of", "--output-format",
        choices=("txt", "json", "jsonl", "csv"),
        help="Output format. Defaults from the -o extension, otherwise txt. With no -o, this format is written to stdout.",
    )
    color = parser.add_mutually_exclusive_group()
    color.add_argument("--color", action="store_true", help="Force colored output.")
    color.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument("-H", "--headers", action="append", help="Extra request header. Repeatable. May contain FUZZ in URL mode.")
    parser.add_argument("-c", "--cookies", help="Cookies, for example session=abc; user=admin. May contain FUZZ in URL mode.")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects.")
    parser.add_argument("--max-redirects", type=int, default=10, help="Redirect limit when following.")
    parser.add_argument("-p", "--proxy", help="Proxy URL. A missing scheme defaults to http://.")
    parser.add_argument("--base64", action="store_true", help="Base64-encode each payload before injection.")
    parser.add_argument("--user-agent", help="User-Agent. Overrides the default and any User-Agent header.")
    parser.add_argument("--request-file", help="Raw HTTP request file. FUZZ is replaced in file order.")
    parser.add_argument("--rps", type=float, help="Global request rate limit.")
    parser.add_argument("--delay", type=float, default=0.0, help="Minimum seconds between request starts. Combined with --rps by using the slower one.")
    parser.add_argument("--encoding", default="utf-8", help="Wordlist encoding. Falls back to latin-1.")
    parser.add_argument("-x", "--extensions", help="Extensions to append, for example php,html.")
    parser.add_argument("--prefix", default="", help="Literal string added before each payload.")
    parser.add_argument("--suffix", default="", help="Literal string added after each payload.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show connection errors and responses that would be hidden only because they are 404.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds.")
    parser.add_argument(
        "--transform",
        help="Extra variants of each word: upper, lower, cap, reverse, append_TEXT, prepend_TEXT.",
    )
    parser.add_argument("--randomize", action="store_true", help="Shuffle the wordlist.")
    parser.add_argument("--seed", type=int, help="Seed for --randomize.")
    parser.add_argument(
        "--multi-fuzz",
        choices=("same", "combo"),
        help="same: every FUZZ gets the current payload. combo: cartesian product across FUZZ slots.",
    )
    parser.add_argument("--silent", action="store_true", help="Print hits only. Errors are still reported.")
    parser.add_argument("--no-encode", action="store_true", help="Insert payloads raw. By default payloads in the URL or request line are percent-encoded.")
    parser.add_argument("--no-dedup", action="store_true", help="Keep duplicate payloads.")
    parser.add_argument("--keep-comments", action="store_true", help="Do not skip wordlist lines that start with #.")
    parser.add_argument("--dry-run", action="store_true", help="Print the requests that would be sent and do not connect.")
    parser.add_argument(
        "-ac", "--auto-calibrate",
        action="store_true",
        help="Send one random baseline request and hide later responses with the same size, word count, and line count.",
    )
    ssl = parser.add_mutually_exclusive_group()
    ssl.add_argument(
        "--ignore-ssl",
        dest="verify_ssl",
        action="store_false",
        help="Do not verify TLS certificates.",
    )
    ssl.add_argument(
        "--no-ignore-ssl",
        dest="verify_ssl",
        action="store_true",
        help="Verify TLS certificates.",
    )
    parser.set_defaults(verify_ssl=False)
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.threads < 1:
        die("--threads must be at least 1")
    if args.timeout <= 0:
        die("--timeout must be a positive number")
    if args.rps is not None and args.rps <= 0:
        die("--rps must be a positive number")
    if args.delay < 0:
        die("--delay cannot be negative")
    if args.max_redirects < 0:
        die("--max-redirects cannot be negative")
    if args.request_file and args.data is not None:
        die("use either --request-file or --data, not both")
    if args.seed is not None and not args.randomize:
        die("--seed requires --randomize")

    if args.extensions:
        extensions = [ext.strip().lstrip(".") for ext in args.extensions.split(",") if ext.strip()]
        if not extensions:
            die("--extensions must contain at least one extension")
        for ext in extensions:
            if any(ch in ext for ch in "/\\ \t"):
                die(f"extension {ext!r} contains whitespace or a slash")
        args.extensions = extensions
    else:
        args.extensions = []

    if args.method:
        args.method = args.method.upper()
    elif args.data is not None:
        args.method = "POST"
    else:
        args.method = "GET"

    args.filter_codes = parse_int_set(args.filter_code, "--filter-code") if args.filter_code else set()
    args.match_codes = parse_int_set(args.match_code, "--match-code") if args.match_code else None
    args.filter_sizes = parse_int_set(args.filter_size, "--filter-size") if args.filter_size else set()
    args.match_sizes = parse_int_set(args.match_size, "--match-size") if args.match_size else None
    args.filter_word_counts = parse_int_set(args.filter_words, "--filter-words") if args.filter_words else set()
    args.match_word_counts = parse_int_set(args.match_words, "--match-words") if args.match_words else None
    args.filter_line_counts = parse_int_set(args.filter_lines, "--filter-lines") if args.filter_lines else set()
    args.match_line_counts = parse_int_set(args.match_lines, "--match-lines") if args.match_lines else None

    try:
        args.match_regex_compiled = re.compile(args.match_regex) if args.match_regex else None
    except re.error as exc:
        die(f"invalid --match-regex: {exc}")
    try:
        args.filter_regex_compiled = re.compile(args.filter_regex) if args.filter_regex else None
    except re.error as exc:
        die(f"invalid --filter-regex: {exc}")

    args.header_pairs = []
    for raw in args.headers or []:
        args.header_pairs.append(parse_header_pair(raw, "--headers"))
    args.cookie_pairs = parse_cookie_string(args.cookies) if args.cookies else []
    args.match_header_pairs = []
    for raw in args.match_header or []:
        args.match_header_pairs.append(parse_header_pair(raw, "--match-header"))

    if args.output_format is None:
        if args.output:
            suffix = Path(args.output).suffix.lower()
            args.output_format = {".json": "json", ".jsonl": "jsonl", ".csv": "csv"}.get(suffix, "txt")
        else:
            args.output_format = "txt"

    args.proxy = normalize_proxy(args.proxy)

    if not args.request_file:
        if not args.url:
            die("pass -u/--url, or pass --request-file")
        parsed = urlparse(args.url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            die("URL must start with http:// or https:// and include a host")
        # Prefix and suffix are literal payload text, not extra placeholders.
        blobs = [args.url, args.data or "", args.user_agent or ""]
        blobs.extend(f"{key}:{value}" for key, value in args.header_pairs)
        blobs.extend(f"{key}={value}" for key, value in args.cookie_pairs)
        if not any(PLACEHOLDER in blob for blob in blobs):
            die(
                "put FUZZ in the URL, --data, --user-agent, --headers, or --cookies "
                "(example: http://127.0.0.1/FUZZ)"
            )
    return args


def normalize_proxy(proxy: str | None) -> str | None:
    if not proxy:
        return None
    if "://" not in proxy:
        return "http://" + proxy
    return proxy


# --- wordlist and payloads -------------------------------------------------

def read_text_lines(path: str, encoding: str) -> list[str]:
    if path == "-":
        return sys.stdin.read().splitlines()
    file_path = Path(path)
    if not file_path.is_file():
        die(f"wordlist not found: {path}")
    try:
        return file_path.read_text(encoding=encoding).splitlines()
    except UnicodeDecodeError:
        sys.stderr.write(
            f"[!] Warning: could not read {path} as {encoding}. Retrying as latin-1.\n"
        )
        return file_path.read_text(encoding="latin-1").splitlines()


def load_wordlist(path: str, encoding: str, keep_comments: bool, dedup: bool) -> list[str]:
    words: list[str] = []
    seen: set[str] = set()
    for line in read_text_lines(path, encoding):
        word = line.strip()
        if not word:
            continue
        if not keep_comments and word.startswith("#"):
            continue
        if dedup and word in seen:
            continue
        seen.add(word)
        words.append(word)
    if not words:
        die(f"wordlist {path} has no usable words")
    return words


def dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def transform_variants(word: str, spec: str | None, dedup_variants: bool) -> list[str]:
    """Return the original word plus one variant per transform.

    Transforms are not a pipeline. `upper,append_1` yields WORD and word1,
    both derived from the original word.
    """
    variants = [word]
    if not spec:
        return variants
    for raw in spec.split(","):
        name = raw.strip()
        if not name:
            continue
        if name == "upper":
            variants.append(word.upper())
        elif name == "lower":
            variants.append(word.lower())
        elif name == "cap":
            variants.append(word.capitalize())
        elif name == "reverse":
            variants.append(word[::-1])
        elif name.startswith("append_"):
            variants.append(word + name.split("_", 1)[1])
        elif name.startswith("prepend_"):
            variants.append(name.split("_", 1)[1] + word)
        else:
            die(
                f"unknown transform {name!r}. "
                "Use upper, lower, cap, reverse, append_TEXT, or prepend_TEXT."
            )
    return dedupe(variants) if dedup_variants else variants


def expand_word(
    word: str,
    transforms: str | None,
    extensions: list[str],
    prefix: str,
    suffix: str,
    use_base64: bool,
    dedup_variants: bool,
) -> list[str]:
    payloads: list[str] = []
    for variant in transform_variants(word, transforms, dedup_variants):
        base = f"{prefix}{variant}{suffix}"
        payloads.append(base)
        for ext in extensions:
            payloads.append(f"{base}.{ext}")
    if use_base64:
        payloads = [base64.b64encode(item.encode("utf-8")).decode("ascii") for item in payloads]
    return dedupe(payloads) if dedup_variants else payloads


def build_payloads(words: list[str], args: argparse.Namespace) -> list[str]:
    dedup_variants = not args.no_dedup
    payloads: list[str] = []
    seen: set[str] = set()
    for word in words:
        for payload in expand_word(
            word,
            args.transform,
            args.extensions,
            args.prefix,
            args.suffix,
            args.base64,
            dedup_variants,
        ):
            if dedup_variants and payload in seen:
                continue
            seen.add(payload)
            payloads.append(payload)
    if not payloads:
        die("no payloads to send")
    return payloads


def order_words(words: list[str], randomize: bool, seed: int | None) -> list[str]:
    if not randomize:
        return list(words)
    copied = list(words)
    random.Random(seed).shuffle(copied)
    return copied


def values_for(index: int, payloads: list[str], slots: int, combo: bool) -> tuple[str, ...]:
    """Map a request index to the payload tuple for that request.

    Combo treats the index as a mixed-radix number so workers can share the
    sequence without building every tuple in memory.
    """
    if slots < 1:
        raise ValueError("request has no FUZZ placeholders")
    if not combo:
        payload = payloads[index]
        return (payload,) * slots
    base = len(payloads)
    digits: list[str] = []
    number = index
    for _ in range(slots):
        digits.append(payloads[number % base])
        number //= base
    return tuple(reversed(digits))


def request_total(payload_count: int, slots: int, combo: bool) -> int:
    if payload_count < 1 or slots < 1:
        return 0
    if combo and slots > 1:
        return payload_count ** slots
    return payload_count


# --- request rendering -----------------------------------------------------

def placeholder_count(text: str) -> int:
    return text.count(PLACEHOLDER)


def render_text(text: str, values: Iterator[str], encode: bool) -> str:
    parts = text.split(PLACEHOLDER)
    rendered: list[str] = []
    for index, part in enumerate(parts):
        rendered.append(part)
        if index == len(parts) - 1:
            break
        try:
            value = next(values)
        except StopIteration:
            raise ValueError("not enough payloads for FUZZ placeholders") from None
        rendered.append(quote(value, safe="") if encode else value)
    return "".join(rendered)


def sanitize(text: str) -> str:
    return text.replace("\r", "\\r").replace("\n", "\\n")


@dataclass
class URLRequest:
    """URL-mode request. Placeholders are filled URL, headers, cookies, then body."""

    method: str
    url: str
    headers: list[tuple[str, str]]
    cookies: list[tuple[str, str]]
    body: str | None
    encode_url: bool

    @property
    def slots(self) -> int:
        total = placeholder_count(self.url)
        for key, value in self.headers:
            total += placeholder_count(key) + placeholder_count(value)
        for key, value in self.cookies:
            total += placeholder_count(key) + placeholder_count(value)
        if self.body is not None:
            total += placeholder_count(self.body)
        return total

    def render(self, values: tuple[str, ...]) -> tuple[str, str, list[tuple[str, str]], dict[str, str], str | None]:
        if len(values) != self.slots:
            raise ValueError(f"expected {self.slots} payloads, got {len(values)}")
        stream = iter(values)
        url = render_text(self.url, stream, self.encode_url)
        headers = [
            (render_text(key, stream, False), render_text(value, stream, False))
            for key, value in self.headers
        ]
        cookies = {
            render_text(key, stream, False): render_text(value, stream, False)
            for key, value in self.cookies
        }
        body = render_text(self.body, stream, False) if self.body is not None else None
        headers, cookies = peel_transport_headers(headers, cookies)
        try:
            next(stream)
        except StopIteration:
            return self.method, url, headers, cookies, body
        raise ValueError("payloads were left unused")


def load_request_text(path: str) -> str:
    file_path = Path(path)
    if not file_path.is_file():
        die(f"request file not found: {path}")
    # Drop a single trailing newline added by editors. Internal newlines stay.
    text = file_path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    if text.endswith("\n"):
        text = text[:-1]
    if not text.strip():
        die(f"request file is empty: {path}")
    return text


def request_file_slots(text: str) -> int:
    return placeholder_count(text)


def render_raw_request(text: str, values: tuple[str, ...], encode_request_line: bool) -> str:
    """Replace FUZZ in file order. Only the request line is percent-encoded."""
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
        has_body = True
    else:
        head, body = text, ""
        has_body = False
    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError("request file is missing the request line")
    stream = iter(values)
    request_line = render_text(lines[0], stream, encode_request_line)
    rest = render_text("\n".join(lines[1:]), stream, False)
    rendered_head = request_line if rest == "" else request_line + "\n" + rest
    if not has_body:
        rendered = rendered_head
    else:
        rendered = rendered_head + "\n\n" + render_text(body, stream, False)
    try:
        next(stream)
    except StopIteration:
        return rendered
    raise ValueError("payloads were left unused")


def parse_http_message(
    text: str,
    scheme: str,
    fallback_host: str | None,
) -> tuple[str, str, list[tuple[str, str]], str | None]:
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, None
    lines = head.split("\n")
    bits = lines[0].split(" ")
    if len(bits) < 2 or not bits[0] or not bits[1]:
        raise ValueError(f"bad request line: {lines[0]!r}")
    method, target = bits[0].upper(), bits[1]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        if ":" not in line:
            raise ValueError(f"bad header line: {line!r}")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ValueError(f"bad header line: {line!r}")
        headers.append((key, value))
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        host = fallback_host
        for key, value in headers:
            if key.lower() == "host" and value:
                host = value
                break
        if not host:
            raise ValueError("request has no Host header and -u did not provide one")
        path = target if target.startswith("/") else "/" + target
        url = f"{scheme}://{host}{path}"
    return method, url, headers, body


def header_value(headers: list[tuple[str, str]], name: str) -> str | None:
    for key, value in headers:
        if key.lower() == name.lower():
            return value
    return None


def cookies_from_header(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in value.split(";"):
        piece = part.strip()
        if not piece or "=" not in piece:
            continue
        key, cookie_value = piece.split("=", 1)
        key = key.strip()
        if key:
            cookies[key] = cookie_value.strip()
    return cookies


def peel_transport_headers(
    headers: list[tuple[str, str]],
    cookies: dict[str, str],
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Drop headers requests manages, and fold Cookie into the cookie jar."""
    cleaned: list[tuple[str, str]] = []
    for key, value in headers:
        lowered = key.lower()
        if lowered == "cookie":
            cookies.update(cookies_from_header(value))
            continue
        if lowered in HOP_HEADERS:
            continue
        cleaned.append((key, value))
    return cleaned, cookies


def apply_static_overlays(
    headers: list[tuple[str, str]],
    args: argparse.Namespace,
) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Apply CLI headers, user-agent, and cookies onto a rendered request file."""
    cleaned, cookies = peel_transport_headers(headers, {})

    if args.user_agent:
        cleaned = [item for item in cleaned if item[0].lower() != "user-agent"]
        cleaned.insert(0, ("User-Agent", args.user_agent))
    elif header_value(cleaned, "user-agent") is None:
        cleaned.insert(0, ("User-Agent", DEFAULT_USER_AGENT))

    for key, value in args.header_pairs:
        if key.lower() == "cookie":
            cookies.update(cookies_from_header(value))
            continue
        if key.lower() in HOP_HEADERS:
            continue
        cleaned = [item for item in cleaned if item[0].lower() != key.lower()]
        cleaned.append((key, value))
    for key, value in args.cookie_pairs:
        cookies[key] = value
    return cleaned, cookies


def scheme_and_host(url: str | None) -> tuple[str, str | None]:
    if not url:
        return "http", None
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    return scheme, parsed.netloc or None


def make_renderer(args: argparse.Namespace) -> tuple[int, Callable[[tuple[str, ...]], tuple]]:
    """Return the placeholder count and a function that builds one request."""
    encode = not args.no_encode
    if args.request_file:
        raw = load_request_text(args.request_file)
        slots = request_file_slots(raw)
        if slots < 1:
            die("request file does not contain FUZZ")
        for key, value in args.header_pairs:
            if PLACEHOLDER in key or PLACEHOLDER in value:
                die("in --request-file mode, put FUZZ in the file rather than in --headers")
        for key, value in args.cookie_pairs:
            if PLACEHOLDER in key or PLACEHOLDER in value:
                die("in --request-file mode, put FUZZ in the file rather than in --cookies")
        if args.user_agent and PLACEHOLDER in args.user_agent:
            die("in --request-file mode, put FUZZ in the file rather than in --user-agent")
        scheme, fallback_host = scheme_and_host(args.url)
        if args.url:
            parsed = urlparse(args.url)
            if parsed.scheme not in ("http", "https"):
                die("-u used with --request-file must be an http:// or https:// URL")

        def render(values: tuple[str, ...]) -> tuple:
            rendered = render_raw_request(raw, values, encode)
            method, url, headers, body = parse_http_message(rendered, scheme, fallback_host)
            headers, cookies = apply_static_overlays(headers, args)
            return method, url, headers, cookies, body

        # Fail fast when the template itself cannot be parsed.
        try:
            render(("x",) * slots)
        except ValueError as exc:
            die(f"request file could not be parsed: {exc}")
        return slots, render

    headers = [("User-Agent", args.user_agent or DEFAULT_USER_AGENT)]
    for key, value in args.header_pairs:
        if key.lower() == "user-agent":
            if args.user_agent:
                continue
            headers = [item for item in headers if item[0].lower() != "user-agent"]
        headers.append((key, value))
    spec = URLRequest(
        method=args.method,
        url=args.url,
        headers=headers,
        cookies=list(args.cookie_pairs),
        body=args.data,
        encode_url=encode,
    )
    if spec.slots < 1:
        die("nothing to fuzz: add at least one FUZZ placeholder")
    return spec.slots, spec.render


def payload_label(values: tuple[str, ...]) -> str:
    if len(values) == 1 or len(set(values)) == 1:
        return values[0]
    return "|".join(values)


# --- filters and output ----------------------------------------------------

@dataclass
class Hit:
    status: int
    size: int
    time_ms: int
    words: int
    lines: int
    payload: str
    method: str
    url: str
    final_url: str
    redirects: int
    text: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "size": self.size,
            "time_ms": self.time_ms,
            "words": self.words,
            "lines": self.lines,
            "payload": self.payload,
            "method": self.method,
            "url": self.url,
            "final_url": self.final_url,
            "redirects": self.redirects,
        }


@dataclass
class Filters:
    hide_404: bool
    exclude_codes: set[int]
    match_codes: set[int] | None
    exclude_sizes: set[int]
    match_sizes: set[int] | None
    exclude_words: set[int]
    match_words: set[int] | None
    exclude_lines: set[int]
    match_lines: set[int] | None
    match_regex: re.Pattern[str] | None
    filter_regex: re.Pattern[str] | None
    match_headers: list[tuple[str, str]]
    signatures: set[tuple[int, int, int]] = field(default_factory=set)

    def allow(self, hit: Hit) -> bool:
        if self.match_codes is not None and hit.status not in self.match_codes:
            return False
        if hit.status in self.exclude_codes:
            return False
        if hit.status == 404 and self.hide_404 and self.match_codes is None:
            return False
        if self.match_sizes is not None and hit.size not in self.match_sizes:
            return False
        if hit.size in self.exclude_sizes:
            return False
        if self.match_words is not None and hit.words not in self.match_words:
            return False
        if hit.words in self.exclude_words:
            return False
        if self.match_lines is not None and hit.lines not in self.match_lines:
            return False
        if hit.lines in self.exclude_lines:
            return False
        if (hit.size, hit.words, hit.lines) in self.signatures:
            return False
        if self.match_regex is not None and self.match_regex.search(hit.text) is None:
            return False
        if self.filter_regex is not None and self.filter_regex.search(hit.text) is not None:
            return False
        for key, expected in self.match_headers:
            actual = hit.headers.get(key.lower())
            if actual is None or expected not in actual:
                return False
        return True


def response_headers(response: requests.Response) -> dict[str, str]:
    return {key.lower(): value for key, value in response.headers.items()}


def hit_from_response(
    response: requests.Response,
    payload: str,
    method: str,
    requested_url: str,
    started: float,
) -> Hit:
    text = response.text or ""
    elapsed_ms = int(response.elapsed.total_seconds() * 1000)
    if elapsed_ms == 0:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
    final_url = response.url or requested_url
    return Hit(
        status=response.status_code,
        size=len(response.content),
        time_ms=elapsed_ms,
        words=len(text.split()),
        lines=len(text.splitlines()),
        payload=payload,
        method=method,
        url=requested_url,
        final_url=final_url,
        redirects=len(response.history),
        text=text,
        headers=response_headers(response),
    )


def format_hit(hit: Hit, colors: Colors | None = None) -> str:
    """Format a hit. The first three fields match the historical line shape."""
    painter = colors or Colors(False)
    status = painter.status(hit.status)
    payload = painter.payload(sanitize(hit.payload))
    line = (
        f"[Status: {status}] [Size: {hit.size}] [URL: {hit.url}] "
        f"[Time: {hit.time_ms}ms] [Words: {hit.words}] [Lines: {hit.lines}] "
        f"[Payload: {payload}] [Method: {hit.method}]"
    )
    if hit.redirects:
        line += f" [Redirects: {hit.redirects}]"
    if hit.final_url and hit.final_url != hit.url:
        line += f" [Final: {hit.final_url}]"
    return line


def format_dry(
    method: str,
    url: str,
    headers: list[tuple[str, str]],
    cookies: dict[str, str],
    body: str | None,
    payload: str,
    colors: Colors | None = None,
) -> str:
    painter = colors or Colors(False)
    extras: list[str] = []
    for key, value in headers:
        if key.lower() == "user-agent":
            continue
        extras.append(f"{key}: {sanitize(value)}")
    if cookies:
        extras.append("Cookie: " + "; ".join(f"{key}={sanitize(value)}" for key, value in cookies.items()))
    suffix = ""
    if body is not None:
        suffix += " body=" + sanitize(body)
    if extras:
        suffix += " [" + "; ".join(extras) + "]"
    shown = painter.payload(sanitize(payload))
    verb = painter.paint(method, Fore.CYAN + Style.BRIGHT)
    return f"[Payload: {shown}] {verb} {url}{suffix}"


def hit_fields() -> list[str]:
    return list(Hit(0, 0, 0, 0, 0, "", "", "", "", 0).as_dict())


class ResultSink:
    """Stream hits to a file, or hold them until the end for JSON and stdout tables."""

    def __init__(self, path: str | None, fmt: str) -> None:
        self.path = path
        self.fmt = fmt
        self.rows: list[dict[str, object]] = []
        self.file = None
        self.writer = None
        self.lock = threading.Lock()
        self.finished = False
        self.text_on_stdout = not (path is None and fmt != "txt")
        self.json_on_stdout = path is None and fmt == "json"
        self._store_rows = fmt == "json" or (path is None and fmt in ("csv", "jsonl"))
        if path is None:
            return
        self.file = open(path, "w", encoding="utf-8", newline="")
        if fmt == "csv":
            self.writer = csv.DictWriter(self.file, fieldnames=hit_fields())
            self.writer.writeheader()

    def add(self, hit: Hit) -> None:
        row = hit.as_dict()
        with self.lock:
            if self.finished:
                return
            if self._store_rows:
                self.rows.append(row)
            if self.file is None or self.fmt == "json":
                return
            if self.fmt == "txt":
                self.file.write(format_hit(hit) + "\n")
            elif self.fmt == "jsonl":
                self.file.write(json.dumps(row, ensure_ascii=False) + "\n")
            elif self.fmt == "csv" and self.writer is not None:
                self.writer.writerow(row)
            self.file.flush()

    def finish(self) -> None:
        with self.lock:
            if self.finished:
                return
            self.finished = True
            if self.fmt == "json":
                payload = json.dumps(self.rows, indent=2, ensure_ascii=False) + "\n"
                if self.file is not None:
                    self.file.write(payload)
                if self.json_on_stdout:
                    sys.stdout.write(payload)
                    sys.stdout.flush()
            elif self.path is None and self.fmt == "jsonl":
                for row in self.rows:
                    sys.stdout.write(json.dumps(row, ensure_ascii=False) + "\n")
                sys.stdout.flush()
            elif self.path is None and self.fmt == "csv":
                buffer = io.StringIO()
                writer = csv.DictWriter(buffer, fieldnames=hit_fields())
                writer.writeheader()
                writer.writerows(self.rows)
                sys.stdout.write(buffer.getvalue())
                sys.stdout.flush()
            if self.file is not None:
                self.file.close()
                self.file = None


def filters_from_args(args: argparse.Namespace) -> Filters:
    return Filters(
        hide_404=not args.verbose,
        exclude_codes=set(args.filter_codes),
        match_codes=None if args.match_codes is None else set(args.match_codes),
        exclude_sizes=set(args.filter_sizes),
        match_sizes=None if args.match_sizes is None else set(args.match_sizes),
        exclude_words=set(args.filter_word_counts),
        match_words=None if args.match_word_counts is None else set(args.match_word_counts),
        exclude_lines=set(args.filter_line_counts),
        match_lines=None if args.match_line_counts is None else set(args.match_line_counts),
        match_regex=args.match_regex_compiled,
        filter_regex=args.filter_regex_compiled,
        match_headers=list(args.match_header_pairs),
    )


# --- engine ----------------------------------------------------------------

class RateLimiter:
    """Space request starts so --rps and --delay are both honored."""

    def __init__(self, rps: float | None, delay: float) -> None:
        interval = 0.0
        if rps:
            interval = max(interval, 1.0 / rps)
        if delay:
            interval = max(interval, delay)
        self.interval = interval
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            scheduled = max(now, self._next)
            self._next = scheduled + self.interval
        pause = scheduled - time.monotonic()
        if pause > 0:
            time.sleep(pause)


class Engine:
    def __init__(
        self,
        args: argparse.Namespace,
        console: Console,
        payloads: list[str],
        slots: int,
        render: Callable[[tuple[str, ...]], tuple],
        filters: Filters,
        sink: ResultSink,
    ) -> None:
        self.args = args
        self.console = console
        self.payloads = payloads
        self.slots = slots
        self.render = render
        self.filters = filters
        self.sink = sink
        self.combo = args.multi_fuzz == "combo" and slots > 1
        self.total = request_total(len(payloads), slots, self.combo)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.next_index = 0
        self.completed = 0
        self.hits = 0
        self.errors = 0
        self.limiter = RateLimiter(args.rps, args.delay)
        self.verify = args.verify_ssl

    def _take_index(self) -> int | None:
        with self.lock:
            if self.stop.is_set() or self.next_index >= self.total:
                return None
            index = self.next_index
            self.next_index += 1
            return index

    def _tick(self) -> None:
        with self.lock:
            self.completed += 1
            done = self.completed
            hits = self.hits
            errors = self.errors
        rate = done / max(time.perf_counter() - self.started, 0.001)
        self.console.progress(
            f"[*] {done}/{self.total} ({(done / self.total) * 100:.2f}%)  "
            f"hits: {hits}  errors: {errors}  {rate:.1f} req/s"
        )

    def _record_error(self, payload: str, url: str, exc: BaseException) -> None:
        with self.lock:
            self.errors += 1
        if self.args.verbose:
            detail = str(exc).splitlines()[0][:300] if str(exc) else exc.__class__.__name__
            self.console.error(
                f"[!] Error [Payload: {sanitize(payload)}] [URL: {url or '-'}] "
                f"{exc.__class__.__name__}: {detail}"
            )

    def _send(self, session: requests.Session, index: int) -> None:
        values = values_for(index, self.payloads, self.slots, self.combo)
        label = payload_label(values)
        try:
            method, url, headers, cookies, body = self.render(values)
        except ValueError as exc:
            self._record_error(label, "", exc)
            return
        if self.stop.is_set():
            return
        self.limiter.wait()
        if self.stop.is_set():
            return
        started = time.perf_counter()
        try:
            response = session.request(
                method=method,
                url=url,
                headers=dict(headers),
                cookies=cookies or None,
                data=body.encode("utf-8") if body is not None else None,
                timeout=self.args.timeout,
                allow_redirects=self.args.follow_redirects,
                verify=self.verify,
            )
        except requests.RequestException as exc:
            self._record_error(label, url, exc)
            return
        hit = hit_from_response(response, label, method, url, started)
        if not self.filters.allow(hit):
            return
        line = format_hit(hit, self.console.colors if self.sink.text_on_stdout else None)
        with self.console.lock:
            if self.sink.text_on_stdout:
                if self.console._stderr_tty():
                    sys.stderr.write("\r\033[K")
                    sys.stderr.flush()
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            self.sink.add(hit)
        with self.lock:
            self.hits += 1

    def _worker(self) -> None:
        session = requests.Session()
        session.trust_env = False
        session.verify = self.verify
        session.max_redirects = self.args.max_redirects
        if self.args.proxy:
            session.proxies.update({"http": self.args.proxy, "https": self.args.proxy})
        try:
            while not self.stop.is_set():
                index = self._take_index()
                if index is None:
                    return
                try:
                    self._send(session, index)
                except Exception as exc:
                    self._record_error("", "", exc)
                finally:
                    self._tick()
        finally:
            session.close()

    def calibrate(self) -> None:
        if not self.args.auto_calibrate:
            return
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        token = "cal_" + "".join(random.choice(alphabet) for _ in range(16))
        values = (token,) * self.slots
        try:
            method, url, headers, cookies, body = self.render(values)
        except ValueError as exc:
            self.console.warn(f"[!] Calibration skipped: {exc}")
            return
        session = requests.Session()
        session.trust_env = False
        session.verify = self.verify
        if self.args.proxy:
            session.proxies.update({"http": self.args.proxy, "https": self.args.proxy})
        try:
            started = time.perf_counter()
            response = session.request(
                method=method,
                url=url,
                headers=dict(headers),
                cookies=cookies or None,
                data=body.encode("utf-8") if body is not None else None,
                timeout=self.args.timeout,
                allow_redirects=self.args.follow_redirects,
                verify=self.verify,
            )
        except requests.RequestException as exc:
            self.console.warn(f"[!] Calibration request failed: {exc.__class__.__name__}")
            return
        finally:
            session.close()
        hit = hit_from_response(response, token, method, url, started)
        self.filters.signatures.add((hit.size, hit.words, hit.lines))
        self.console.info(
            f"[*] Calibrated on {token}: status={hit.status} size={hit.size} "
            f"words={hit.words} lines={hit.lines}"
        )

    def dry_run(self) -> int:
        for index in range(self.total):
            values = values_for(index, self.payloads, self.slots, self.combo)
            label = payload_label(values)
            try:
                method, url, headers, cookies, body = self.render(values)
            except ValueError as exc:
                self.console.error(f"[!] Could not render payload {label!r}: {exc}")
                return 1
            self.console.hit(format_dry(method, url, headers, cookies, body, label, self.console.colors))
        self.console.info(f"[*] Dry run: {self.total} requests not sent")
        return 0

    def run(self) -> int:
        if self.total > MAX_COMBO_REQUESTS and self.combo:
            die(
                f"combo mode would send {self.total} requests, above the "
                f"{MAX_COMBO_REQUESTS} safety limit. Narrow the wordlist or use --multi-fuzz same."
            )
        if self.total < 1:
            die("nothing to send")
        self.console.info(
            f"[*] Payloads: {len(self.payloads)}  Placeholders: {self.slots}  "
            f"Requests: {self.total}  Threads: {self.args.threads}"
        )
        tls = "on" if self.verify else "off"
        self.console.info(
            f"[*] Method: {self.args.method if not self.args.request_file else 'from request file'}  "
            f"TLS verify: {tls}"
        )
        if self.args.dry_run:
            return self.dry_run()
        if not self.verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.calibrate()
        self.started = time.perf_counter()
        threads = [
            threading.Thread(target=self._worker, name=f"skiff-{number}", daemon=True)
            for number in range(self.args.threads)
        ]
        for thread in threads:
            thread.start()
        code = 0
        try:
            while any(thread.is_alive() for thread in threads):
                for thread in threads:
                    thread.join(timeout=0.2)
        except KeyboardInterrupt:
            self.stop.set()
            self.console.error("[!] Interrupted")
            code = 130
        finally:
            self.stop.set()
            deadline = time.monotonic() + self.args.timeout + 0.5
            for thread in threads:
                remaining = deadline - time.monotonic()
                thread.join(timeout=max(0.05, remaining))
        elapsed = max(time.perf_counter() - self.started, 0.001)
        self.console.clear_progress()
        self.sink.finish()
        self.console.info(
            f"[*] Done. Requests: {self.completed}  Hits: {self.hits}  "
            f"Errors: {self.errors}  Elapsed: {elapsed:.2f}s  "
            f"Rate: {self.completed / elapsed:.1f} req/s"
        )
        if code == 130:
            return 130
        if self.completed and self.errors == self.completed:
            self.console.error(f"[!] All {self.errors} requests failed")
            return 1
        if self.errors and self.console.silent:
            self.console.error(f"[!] {self.errors} request errors")
        return 0


def execute(args: argparse.Namespace, console: Console) -> int:
    words = load_wordlist(args.wordlist, args.encoding, args.keep_comments, not args.no_dedup)
    words = order_words(words, args.randomize, args.seed)
    console.info(f"[*] Loaded {len(words)} words from {args.wordlist}")
    payloads = build_payloads(words, args)
    slots, render = make_renderer(args)
    filters = filters_from_args(args)
    output_path = args.output
    output_format = args.output_format
    if args.dry_run:
        if args.output:
            console.warn("[!] --dry-run prints requests and does not write --output")
        output_path = None
        output_format = "txt"
    sink = ResultSink(output_path, output_format)
    try:
        engine = Engine(args, console, payloads, slots, render, filters, sink)
        return engine.run()
    finally:
        sink.finish()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    console = Console(Colors(resolve_color(args)), args.silent)
    console.banner()
    try:
        return execute(args, console)
    except KeyboardInterrupt:
        console.error("[!] Interrupted")
        return 130


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("[!] Interrupted\n")
        sys.exit(130)
