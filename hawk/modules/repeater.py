"""Edit a captured HTTP request, then send that copy.

Load a raw request, change the method, path, headers, or body, and optionally
open it in `$VISUAL` or `$EDITOR`. `--print` writes the edited request and
returns before any connection. The host that is contacted has to be in scope.
Loopback is always in scope.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from rich.markup import escape

from hawk import ui
from hawk.workspace import allowed, explain_block, hostname_of, save_request, split_host

_MAX_BYTES = 8 * 1024 * 1024
_DISPLAY_BYTES = 512 * 1024
_MAX_REDIRECTS = 5
_REDIRECTS = {301, 302, 303, 307, 308}


@dataclass
class RawRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    scheme: str | None = None
    declare_length: bool = False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk repeater",
        description="Edit a captured HTTP request, then send that edited copy.",
    )
    parser.add_argument("request", help="Raw HTTP request file.")
    parser.add_argument("--method", help="Replace the method.")
    parser.add_argument("--path", help="Replace the path and query.")
    parser.add_argument("--host", help="Set the Host header. An absolute URL is rewritten too.")
    parser.add_argument("--scheme", choices=("http", "https"), help="Use http or https.")
    parser.add_argument("--header", action="append", default=[], help="Set one header, as 'Name: value'. Replaces that name.")
    parser.add_argument("--remove-header", action="append", default=[], help="Remove every header with this name.")
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--body", help="Replace the body with this text.")
    body.add_argument("--body-file", help="Replace the body with this file.")
    parser.add_argument("--edit", action="store_true", help="Open $VISUAL or $EDITOR after the other edits.")
    parser.add_argument("--print", dest="preview", action="store_true", help="Write the edited request and do not connect.")
    parser.add_argument("--follow", action="store_true", help="Follow redirects that stay in scope.")
    parser.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates.")
    parser.add_argument("--timeout", type=float, default=15, help="Seconds to wait for the response.")
    parser.add_argument("--output", help="Write the response to this file.")
    parser.add_argument("--save-request", help="Store the edited request in the scope workspace.")
    parser.add_argument("--connect", help="Send to HOST or HOST:PORT and keep the Host header.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = Path(args.request)
    if not path.is_file():
        ui.console.print(f"[err]No file named[/err] {escape(args.request)}")
        return 2
    try:
        if path.stat().st_size > _MAX_BYTES:
            ui.console.print("[err]That request is larger than 8 MB.[/err]")
            return 2
        req = parse_raw(path.read_bytes())
        req = apply_edits(req, args)
        if args.edit:
            req = edit_request(req)
    except ValueError as exc:
        ui.console.print(f"[err]{escape(str(exc))}[/err]")
        return 2
    if len(req.body) > _MAX_BYTES:
        ui.console.print("[err]The request body is larger than 8 MB.[/err]")
        return 2
    if args.save_request:
        try:
            saved = save_request(args.save_request, render(req))
        except ValueError as exc:
            ui.console.print(f"[err]{escape(str(exc))}[/err]")
            return 2
        ui.console.print(f"[ok]saved[/ok] {saved}", markup=False)
    if args.preview:
        _write_out(render(req))
        return 0
    try:
        host, _port = endpoint(req, args.connect)
        scheme = effective_scheme(req, _port)
    except ValueError as exc:
        ui.console.print(f"[err]{escape(str(exc))}[/err]")
        return 2
    if scheme not in {"http", "https"}:
        ui.console.print("[err]Only http and https requests can be sent.[/err]")
        return 2
    if not host:
        ui.console.print("[err]The request has no host.[/err] Add a Host header, --host, or --connect.")
        return 2
    if not allowed(host):
        ui.console.print(explain_block(host), markup=False, highlight=False)
        return 2
    try:
        url = request_url(req, args.connect)
    except ValueError as exc:
        ui.console.print(f"[err]{escape(str(exc))}[/err]")
        return 2
    return _send(req, url, args)


def parse_raw(data: bytes) -> RawRequest:
    if not data.strip():
        raise ValueError("The request file is empty.")
    head, body = _split_message(data)
    text = head.decode("latin-1")
    lines = text.splitlines()
    if not lines or not lines[0].strip():
        raise ValueError("The request has no request line.")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("The request line needs a method and a target.")
    method, target = parts[0], parts[1]
    version = parts[2] if len(parts) >= 3 else "HTTP/1.1"
    if not method:
        raise ValueError("The request line needs a method.")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[0] in " \t" and headers:
            name, value = headers[-1]
            headers[-1] = (name, f"{value} {line.strip()}")
            continue
        if ":" not in line:
            raise ValueError(f"Header has no name: {line.strip()}")
        name, value = line.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError("Header has no name.")
        headers.append((name, value.strip()))
    declare = bool(body) or any(name.lower() == "content-length" for name, _value in headers)
    return RawRequest(method.upper(), target, version, headers, body, None, declare)


def apply_edits(req: RawRequest, args) -> RawRequest:
    if args.method:
        req.method = args.method.strip().upper()
        if not req.method:
            raise ValueError("Method is empty.")
    if args.path:
        req.target = replace_path(req.target, args.path.strip())
    if args.host:
        set_host(req, args.host.strip())
    if args.scheme:
        req.scheme = args.scheme
        if "://" in req.target:
            req.target = replace_scheme(req.target, args.scheme)
    for item in args.header:
        if ":" not in item:
            raise ValueError(f"Header needs a name and a value: {item}")
        name, value = item.split(":", 1)
        name = name.strip()
        if not name:
            raise ValueError("Header has no name.")
        if name.lower() == "host":
            set_host(req, value.strip())
        else:
            replace_header(req, name, value.strip())
    for name in args.remove_header:
        remove_header(req, name.strip())
    if args.body is not None:
        req.body = args.body.encode("utf-8")
        req.declare_length = True
        remove_header(req, "Transfer-Encoding")
    elif args.body_file:
        file_path = Path(args.body_file)
        if not file_path.is_file():
            raise ValueError(f"No file named {args.body_file}.")
        if file_path.stat().st_size > _MAX_BYTES:
            raise ValueError("The request body is larger than 8 MB.")
        req.body = file_path.read_bytes()
        req.declare_length = True
        remove_header(req, "Transfer-Encoding")
    return req


def edit_request(req: RawRequest) -> RawRequest:
    editor = (os.environ.get("VISUAL") or os.environ.get("EDITOR") or "").strip()
    if not editor:
        raise ValueError("Set EDITOR or VISUAL to edit the request.")
    fd, name = tempfile.mkstemp(prefix="webhawk-request-", suffix=".http")
    path = Path(name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(render(req))
        try:
            subprocess.run([*shlex.split(editor), str(path)], check=False)
        except OSError as exc:
            raise ValueError(f"Could not run the editor: {exc}") from exc
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ValueError(f"Could not read the edited request: {exc}") from exc
    finally:
        path.unlink(missing_ok=True)
    if not data.strip():
        raise ValueError("The editor saved an empty request.")
    if len(data) > _MAX_BYTES:
        raise ValueError("The edited request is larger than 8 MB.")
    return parse_raw(data)


def render(req: RawRequest) -> bytes:
    """Raw HTTP/1.1 bytes, with CRLF, for preview, edit, and save."""
    target = req.target
    headers: list[tuple[str, str]] = []
    for name, value in req.headers:
        if name.lower() in {"transfer-encoding", "content-length"}:
            continue
        headers.append((name, value))
    if req.declare_length:
        headers.append(("Content-Length", str(len(req.body))))
    lines = [f"{req.method} {target} {req.version or 'HTTP/1.1'}"]
    lines.extend(f"{name}: {value}" for name, value in headers)
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("latin-1", errors="replace") + req.body


def endpoint(req: RawRequest, connect: str | None) -> tuple[str, int | None]:
    """Host and port that will actually be contacted."""
    if connect:
        host, port = split_host(connect.strip())
        return _bare_host(host), _port(port)
    if "://" in req.target:
        parts = urlsplit(req.target)
        return (parts.hostname or ""), parts.port
    host_header = first_header(req, "Host")
    if not host_header:
        return "", None
    host, port = split_host(host_header.strip())
    return _bare_host(host), _port(port)


def request_url(req: RawRequest, connect: str | None) -> str:
    host, port = endpoint(req, connect)
    scheme = effective_scheme(req, port)
    return f"{scheme}://{_netloc(host, port)}{path_and_query(req)}"


def effective_scheme(req: RawRequest, port: int | None) -> str:
    if req.scheme in {"http", "https"}:
        return req.scheme
    if "://" in req.target:
        scheme = urlsplit(req.target).scheme.lower()
        if scheme in {"http", "https"}:
            return scheme
        raise ValueError("Only http and https requests can be sent.")
    if port == 443:
        return "https"
    return "http"


def path_and_query(req: RawRequest) -> str:
    target = req.target.strip()
    if "://" in target:
        parts = urlsplit(target)
        path = parts.path or "/"
        if parts.query:
            return f"{path}?{parts.query}"
        return path
    if target.startswith("/"):
        return target
    if not target:
        return "/"
    return "/" + target


def replace_path(target: str, path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not path.startswith("/") and not path.startswith("?"):
        path = "/" + path
    if "://" not in target:
        return path
    parts = urlsplit(target)
    if "?" in path:
        new_path, query = path.split("?", 1)
    else:
        new_path, query = path, ""
    if new_path.startswith("?"):
        new_path = "/"
    return urlunsplit((parts.scheme, parts.netloc, new_path or "/", query, ""))


def replace_scheme(target: str, scheme: str) -> str:
    parts = urlsplit(target)
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))


def set_host(req: RawRequest, value: str) -> None:
    if not value:
        raise ValueError("Host is empty.")
    replace_header(req, "Host", value)
    if "://" not in req.target:
        return
    parts = urlsplit(req.target)
    host, port = split_host(value)
    host = _bare_host(host)
    number = _port(port)
    if number is None:
        number = parts.port
    req.target = urlunsplit((parts.scheme, _netloc(host, number), parts.path, parts.query, parts.fragment))


def replace_header(req: RawRequest, name: str, value: str) -> None:
    kept = [(item, current) for item, current in req.headers if item.lower() != name.lower()]
    kept.append((name, value))
    req.headers = kept


def remove_header(req: RawRequest, name: str) -> None:
    req.headers = [(item, value) for item, value in req.headers if item.lower() != name.lower()]


def first_header(req: RawRequest, name: str) -> str | None:
    for item, value in req.headers:
        if item.lower() == name.lower():
            return value
    return None


def _send(req: RawRequest, url: str, args) -> int:
    method = req.method
    body = req.body if req.declare_length or req.body else b""
    send_body: bytes | None = body if req.declare_length or body else None
    headers = _send_headers(req, args.connect)
    # trust_env is off so the host that was allowed is the host that is contacted.
    try:
        with httpx.Client(
            timeout=args.timeout,
            verify=not args.insecure,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            current = url
            response: httpx.Response | None = None
            body = b""
            for hop in range(_MAX_REDIRECTS + 1):
                with client.stream(method, current, headers=headers, content=send_body) as response:
                    followed = (
                        args.follow
                        and response.status_code in _REDIRECTS
                        and hop < _MAX_REDIRECTS
                    )
                    location = response.headers.get("location", "").strip() if followed else ""
                    if followed and location:
                        nxt = urljoin(str(response.url), location)
                        host = hostname_of(nxt)
                        if not host or not allowed(nxt) or urlsplit(nxt).scheme not in {"http", "https"}:
                            raw = _response_bytes(response, _read_capped(response, _MAX_BYTES))
                            _show_bytes(response, raw)
                            ui.console.print(explain_block(host or nxt), markup=False, highlight=False)
                            return 2
                        _read_capped(response, 65_536)
                        if response.status_code in {301, 302, 303}:
                            method = "GET"
                            send_body = None
                        current = nxt
                        headers = [(name, value) for name, value in headers if name.lower() != "host"]
                        continue
                    body = _read_capped(response, _MAX_BYTES)
                    break
    except httpx.HTTPError as exc:
        ui.console.print(f"[err]Request failed:[/err] {escape(str(exc))}")
        return 1
    if response is None:
        ui.console.print("[err]Request failed.[/err]")
        return 1
    raw = _response_bytes(response, body)
    if args.output:
        try:
            Path(args.output).write_bytes(raw)
        except OSError as exc:
            ui.console.print(f"[err]Could not write the response:[/err] {escape(str(exc))}")
            return 1
    _show_bytes(response, raw)
    return 0


def _send_headers(req: RawRequest, connect: str | None) -> list[tuple[str, str]]:
    """Drop framing headers. Keep Host only when --connect chose a different target."""
    pairs: list[tuple[str, str]] = []
    for name, value in req.headers:
        low = name.lower()
        if low in {"content-length", "transfer-encoding"}:
            continue
        if low == "host" and not connect:
            continue
        pairs.append((name, value))
    return pairs


def _read_capped(response: httpx.Response, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        if total >= limit:
            break
        piece = chunk[: limit - total]
        chunks.append(piece)
        total += len(piece)
    return b"".join(chunks)


def _show_bytes(response: httpx.Response, raw: bytes) -> None:
    sent = response.request
    sys.stdout.write(f"sent {sent.method} {sent.url}\n")
    sys.stdout.flush()
    _write_out(raw[:_DISPLAY_BYTES])
    if len(raw) > _DISPLAY_BYTES:
        ui.console.print(f"[muted]Response truncated at {_DISPLAY_BYTES} bytes.[/muted]")


def _response_bytes(response: httpx.Response, body: bytes) -> bytes:
    reason = response.reason_phrase or ""
    lines = [f"{response.http_version} {response.status_code} {reason}".rstrip()]
    lines.extend(f"{name}: {value}" for name, value in response.headers.items())
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="replace")
    room = max(0, _MAX_BYTES - len(head))
    return head + body[:room]


def _write_out(data: bytes) -> None:
    stream = sys.stdout
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        if not data.endswith(b"\n"):
            buffer.write(b"\n")
        buffer.flush()
        return
    text = data.decode("latin-1", errors="replace")
    stream.write(text)
    if not text.endswith("\n"):
        stream.write("\n")
    stream.flush()


def _split_message(data: bytes) -> tuple[bytes, bytes]:
    found: list[tuple[int, bytes]] = []
    for sep in (b"\r\n\r\n", b"\n\n"):
        index = data.find(sep)
        if index != -1:
            found.append((index, sep))
    if not found:
        return data, b""
    index, sep = min(found)
    return data[:index], data[index + len(sep) :]


def _bare_host(host: str) -> str:
    return host.strip().strip("[]")


def _port(value: str | int | None) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        number = value
    else:
        text = str(value).strip()
        if not text.isdigit():
            raise ValueError(f"Port {value} is not a number.")
        number = int(text)
    if not 1 <= number <= 65535:
        raise ValueError(f"Port {number} is out of range.")
    return number


def _netloc(host: str, port: int | None) -> str:
    shown = f"[{host}]" if ":" in host else host
    if port:
        return f"{shown}:{port}"
    return shown
