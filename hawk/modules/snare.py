"""Catch browser traffic on localhost and keep the in-scope exchanges.

Snare listens on 127.0.0.1. Each in-scope request is written under requests/
and the response under responses/, with the same file name. The URL is added
to the shared list. A host outside scope is forwarded and left out of the
workspace. From the WebHawk prompt the listener stays up and the prompt
returns. `clutch` lists those files. Nothing here imports mitmproxy.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from hawk.workspace import allowed, requests_dir, responses_dir, urls_path, workspace_dir

_MAX_BODY = 1_000_000
_FORWARD_CAP = 8_000_000
_HEAD_CAP = 65_536
_MARK = "snare"
_TAG = "the web the browser flies into"
_ART = (
    r"              \   |   /",
    r"               \  |  /",
    "            .---\\ | /---.",
    "           /     \\|/     \\",
    r"          |     snare     |",
    "           \\     /|\\     /",
    r"            '---/ | \---'",
    "               /  |  \\",
    "              /   |   \\",
    r"                [web]",
)
_CYAN = "\033[1;96m"
_YELLOW = "\033[1;93m"
_MAGENTA = "\033[1;95m"
_WHITE = "\033[1;97m"
_GREEN = "\033[1;92m"
_RED = "\033[1;91m"
_DIM = "\033[2;96m"
_RESET = "\033[0m"
_HOP = {
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "transfer-encoding",
    "proxy-authorization",
}
_LOCK = threading.Lock()


class _Bad(Exception):
    pass


class _TooLarge(Exception):
    pass


class CaError(Exception):
    pass


@dataclass
class Settings:
    port: int = 8080
    timeout: float = 10.0
    insecure: bool = False
    max_body: int = _MAX_BODY
    plain: bool = False
    bound_port: int = 0
    ready: threading.Event | None = None
    forward_limit: int = field(init=False)

    def __post_init__(self) -> None:
        self.forward_limit = max(self.max_body, _FORWARD_CAP)


@dataclass
class _Message:
    line: str
    headers: list[tuple[str, str]]


class _Reader:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    def read_head(self) -> bytes:
        while b"\r\n\r\n" not in self.buf and b"\n\n" not in self.buf:
            chunk = self.sock.recv(_HEAD_CAP)
            if not chunk:
                break
            self.buf += chunk
            if len(self.buf) > _HEAD_CAP:
                raise _TooLarge()
        for marker in (b"\r\n\r\n", b"\n\n"):
            if marker in self.buf:
                head, self.buf = self.buf.split(marker, 1)
                return head
        raise _Bad()

    def read_exact(self, count: int) -> bytes:
        while len(self.buf) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.buf += chunk
        if len(self.buf) < count:
            raise _Bad()
        data, self.buf = self.buf[:count], self.buf[count:]
        return data

    def read_line(self) -> bytes:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.buf += chunk
            if len(self.buf) > _HEAD_CAP:
                raise _TooLarge()
        if b"\n" not in self.buf:
            raise _Bad()
        line, self.buf = self.buf.split(b"\n", 1)
        return line.rstrip(b"\r")

    def read_rest(self, limit: int) -> bytes:
        while len(self.buf) < limit:
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            self.buf += chunk
        data = self.buf[:limit]
        self.buf = self.buf[limit:]
        if len(data) >= limit and self.buf:
            raise _TooLarge()
        return data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk snare",
        description=(
            "Listen on localhost and keep in-scope requests and responses. "
            "In the console the prompt stays free. clutch lists the saved files."
        ),
    )
    parser.add_argument("--plain", action="store_true", help="Skip the banner and the row colors.")
    parser.add_argument("--port", type=int, default=8080, help="Port on 127.0.0.1. 0 picks a free port.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Seconds for a socket. Default 10.")
    parser.add_argument("--insecure", action="store_true", help="Do not verify upstream TLS certificates.")
    parser.add_argument(
        "--max-body",
        type=int,
        default=_MAX_BODY,
        help=f"Bytes kept from each body. Default {_MAX_BODY}.",
    )
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("ca", help="Write the CA, if needed, and print its certificate path.")
    sub.add_parser("status", help="Show the port and where saved requests go.")
    sub.add_parser("stop", help="Close the listener and leave the saved files in place.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "stop":
        return stop_listener()
    if args.command == "status":
        return print_status()
    if args.port < 0 or args.port > 65535:
        _say("The port has to be from 0 to 65535.")
        return 2
    if args.timeout <= 0:
        _say("Timeout must be greater than 0.")
        return 2
    if args.max_body < 1:
        _say("The body cap has to be at least 1 byte.")
        return 2
    if args.command == "ca":
        if not args.plain:
            _show_banner()
        return _print_ca()
    if not args.plain:
        _show_banner()
    settings = Settings(
        port=args.port,
        timeout=args.timeout,
        insecure=args.insecure,
        max_body=args.max_body,
        plain=args.plain,
    )
    if console_attached():
        return begin(settings)
    _say("Ctrl-C stops this listener. From the WebHawk prompt, snare stays up beside the other modules.")
    stop = threading.Event()
    try:
        return listen(settings, stop)
    except KeyboardInterrupt:
        stop.set()
        return 0


def listen(settings: Settings, stop: threading.Event) -> int:
    """Accept browser connections until stop is set. Bind address is 127.0.0.1."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", settings.port))
        sock.listen(64)
        sock.settimeout(0.2)
        settings.bound_port = sock.getsockname()[1]
    except OSError as exc:
        _say(f"Could not listen on 127.0.0.1:{settings.port}.")
        if settings.ready is not None:
            settings.ready.set()
        sock.close()
        return 1
    _say(f"listening on 127.0.0.1:{settings.bound_port}")
    try:
        cert, _key = ensure_ca()
        _say(f"CA {cert}")
        _say("Trust that certificate in the test browser.")
    except CaError as exc:
        _say(str(exc))
        _say("HTTP still logs. HTTPS inside scope needs openssl.")
    _emit_guide(settings.plain)
    if settings.ready is not None:
        settings.ready.set()
    try:
        while not stop.is_set():
            try:
                conn, addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if not _loopback_peer(addr[0]):
                conn.close()
                continue
            threading.Thread(target=_handle_client, args=(conn, settings), daemon=True).start()
    finally:
        sock.close()
        if settings.ready is not None:
            settings.ready.set()
    return 0


_redraw: Callable[[str], None] | None = None
_job_lock = threading.Lock()
_job_thread: threading.Thread | None = None
_job_stop: threading.Event | None = None
_job_settings: Settings | None = None
_print_lock = threading.Lock()


def attach_console(redraw: Callable[[str], None] | None) -> None:
    """Remember that the WebHawk prompt is active. None detaches it."""
    global _redraw
    _redraw = redraw


def console_attached() -> bool:
    return _redraw is not None


def job_tag() -> str:
    """Prompt marker while the background listener is up, else an empty string."""
    settings = _job_settings
    if settings is None or not settings.bound_port or not _job_alive():
        return ""
    return f"snare:{settings.bound_port}"


def begin(settings: Settings) -> int:
    """Listen on a background thread and return once the port is bound."""
    global _job_thread, _job_stop, _job_settings
    with _job_lock:
        if _job_alive():
            _announce_alive()
            return 0
        settings.ready = threading.Event()
        stop = threading.Event()
        thread = threading.Thread(target=listen, args=(settings, stop), daemon=True, name="snare")
        _job_stop = stop
        _job_settings = settings
        _job_thread = thread
        thread.start()
    if not settings.ready.wait(30):
        stop.set()
        _say("snare did not bind.")
        return 1
    if settings.bound_port == 0 or not thread.is_alive():
        return 1
    _say("The prompt is free. Other modules keep working.")
    _say("snare stop closes the listener.")
    return 0


def stop_listener(*, quiet: bool = False) -> int:
    """Close the background listener. A quiet stop says nothing when it is already down."""
    with _job_lock:
        thread = _job_thread
        stop = _job_stop
        settings = _job_settings
    if thread is None or not thread.is_alive():
        if not quiet:
            _say("snare is not listening.")
            _emit_guide(False)
        return 0
    if stop is not None:
        stop.set()
    thread.join(3)
    port = settings.bound_port if settings is not None else 0
    _say(f"snare stopped. It was on 127.0.0.1:{port}.")
    _say("The saved files stay where they are.")
    _emit_guide(bool(settings.plain) if settings is not None else False)
    return 0


def print_status() -> int:
    settings = _job_settings
    if settings is not None and settings.bound_port and _job_alive():
        _say(f"listening on 127.0.0.1:{settings.bound_port}")
        _say("The prompt is free. Other modules keep working.")
        _say("snare stop closes the listener.")
        _emit_guide(settings.plain)
        return 0
    _say("snare is not listening.")
    _emit_guide(False)
    return 0


def _job_alive() -> bool:
    thread = _job_thread
    return thread is not None and thread.is_alive()


def _announce_alive() -> None:
    settings = _job_settings
    port = settings.bound_port if settings is not None else 0
    _say(f"snare is already listening on 127.0.0.1:{port}.")
    _emit_guide(bool(settings.plain) if settings is not None else False)
    _say("snare stop closes the listener.")


def ensure_ca() -> tuple[Path, Path]:
    """Return the CA certificate and key, creating them with openssl when missing."""
    root = _snare_dir()
    cert, key = root / "ca.crt", root / "ca.key"
    if cert.is_file() and key.is_file():
        return cert, key
    root.mkdir(parents=True, exist_ok=True)
    config = root / "ca.cnf"
    config.write_text(
        "\n".join(
            [
                "[req]",
                "distinguished_name=dn",
                "x509_extensions=v3_ca",
                "prompt=no",
                "[dn]",
                "CN=WebHawk snare CA",
                "[v3_ca]",
                "basicConstraints=critical,CA:TRUE",
                "keyUsage=critical,keyCertSign,cRLSign",
                "subjectKeyIdentifier=hash",
                "",
            ]
        ),
        encoding="utf-8",
    )
    _openssl(
        [
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            "ca.key",
            "-out",
            "ca.crt",
            "-days",
            "825",
            "-nodes",
            "-config",
            "ca.cnf",
        ],
        root,
    )
    os.chmod(key, 0o600)
    return cert, key


def issue_leaf(host: str) -> tuple[Path, Path]:
    """Return a certificate for one host, signed by the snare CA."""
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", host):
        raise CaError("That host cannot have a certificate.")
    safe = host.replace(":", "_")
    root = _snare_dir() / "leafs"
    cert, key = root / f"{safe}.crt", root / f"{safe}.key"
    with _LOCK:
        if cert.is_file() and key.is_file():
            return cert, key
        ca_cert, ca_key = ensure_ca()
        root.mkdir(parents=True, exist_ok=True)
        try:
            san = f"IP:{ipaddress.ip_address(host)}"
            common = host
        except ValueError:
            san = f"DNS:{host}"
            common = host
        config = root / f"{safe}.cnf"
        config.write_text(
            "\n".join(
                [
                    "[req]",
                    "distinguished_name=dn",
                    "prompt=no",
                    "[dn]",
                    f"CN={common}",
                    "[v3]",
                    "basicConstraints=CA:FALSE",
                    f"subjectAltName={san}",
                    "keyUsage=digitalSignature,keyEncipherment",
                    "extendedKeyUsage=serverAuth",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        _openssl(
            ["req", "-new", "-newkey", "rsa:2048", "-keyout", key.name, "-out", f"{safe}.csr", "-nodes", "-config", config.name],
            root,
        )
        _openssl(
            [
                "x509",
                "-req",
                "-in",
                f"{safe}.csr",
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-CAserial",
                str(_snare_dir() / "ca.srl"),
                "-CAcreateserial",
                "-out",
                cert.name,
                "-days",
                "30",
                "-extfile",
                config.name,
                "-extensions",
                "v3",
            ],
            root,
        )
        os.chmod(key, 0o600)
    return cert, key


def format_banner(color: bool) -> str:
    return _banner(_ART, _MARK, _TAG, color)


def format_row(
    method: str,
    status: str,
    size: int,
    host: str,
    path: str,
    color: bool,
    *,
    name: str = "",
    note: str = "",
) -> str:
    fields = [method, status, str(size), host, path]
    if name:
        fields.append(name)
    if note:
        fields.append(note)
    plain = "\t".join(fields)
    if not color:
        return plain
    paint = _status_color(status)
    filebit = f"  {_MAGENTA}{name}{_RESET}" if name else ""
    suffix = f" {_YELLOW}{note}{_RESET}" if note else ""
    return (
        f"{_CYAN}{method:<7}{_RESET} {paint}{status:<3}{_RESET} {_DIM}{size:>8}{_RESET}  "
        f"{_WHITE}{host} {path}{_RESET}{filebit}{suffix}"
    )


def format_guide(color: bool) -> str:
    """Where a capture lands, and the commands that open it."""
    requests = _display(requests_dir())
    responses = _display(responses_dir())
    rows = [
        ("requests", f"{requests}/example.com-snare-0001.http"),
        ("responses", f"{responses}/example.com-snare-0001.http"),
        ("view", "clutch"),
        ("", "clutch show example.com-snare-0001.http"),
        ("compare", "diff example.com-snare-0001.http example.com-snare-0002.http"),
    ]
    lines: list[str] = []
    for label, value in rows:
        if not color:
            lines.append(f"{label:<10}{value}" if label else f"{'':10}{value}")
            continue
        shown = value
        for word in ("clutch show", "clutch", "diff"):
            if shown.startswith(word):
                shown = f"{_MAGENTA}{word}{_RESET}{_WHITE}" + shown[len(word):]
                break
        painted = f"{_CYAN}{label:<10}{_RESET}" if label else " " * 10
        lines.append(f"{painted}{_WHITE}{shown}{_RESET}")
    return "\n".join(lines)


def format_skip(host: str, color: bool) -> str:
    plain = f"skipped\t{host}"
    if not color:
        return plain
    return f"{_YELLOW}skipped{_RESET}  {_DIM}{host}{_RESET}"


def format_tunnel(host: str, port: int, color: bool) -> str:
    plain = f"tunnel\t{host}:{port}"
    if not color:
        return plain
    return f"{_YELLOW}tunnel{_RESET}   {_DIM}{host}:{port}{_RESET}"


def _print_ca() -> int:
    try:
        cert, _key = ensure_ca()
    except CaError as exc:
        _say(str(exc))
        return 1
    print(cert)
    _say("Trust that certificate in the test browser. The key stays beside it.")
    return 0


def _handle_client(conn: socket.socket, settings: Settings) -> None:
    try:
        conn.settimeout(settings.timeout)
        reader = _Reader(conn)
        message = _parse_head(reader.read_head())
        if message is None:
            _send_status(conn, 400, "Bad request")
            return
        parts = _request_parts(message.line)
        if parts is None:
            _send_status(conn, 400, "Bad request")
            return
        method, target, version = parts
        if method.upper() == "CONNECT":
            _handle_connect(conn, target, settings)
            return
        _handle_exchange(conn, reader, message, method, target, version, settings, scheme=None, default_port=None)
    except _TooLarge:
        _send_status(conn, 413, "Body is too large")
    except (_Bad, TimeoutError, ConnectionError, ssl.SSLError):
        return
    except Exception:
        _say("snare dropped one connection.")
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _handle_connect(conn: socket.socket, target: str, settings: Settings) -> None:
    host, port = _split_authority(target)
    if not host:
        _send_status(conn, 400, "Bad request")
        return
    port = 443 if port is None else port
    if not allowed(host):
        _tunnel(conn, host, port, settings)
        return
    try:
        cert, key = issue_leaf(host)
    except CaError as exc:
        _say(str(exc))
        _send_status(conn, 502, "HTTPS is unavailable")
        return
    conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    tls = context.wrap_socket(conn, server_side=True)
    try:
        tls.settimeout(settings.timeout)
        reader = _Reader(tls)
        message = _parse_head(reader.read_head())
        if message is None:
            return
        parts = _request_parts(message.line)
        if parts is None:
            return
        method, target, version = parts
        _handle_exchange(
            tls,
            reader,
            message,
            method,
            target,
            version,
            settings,
            scheme="https",
            default_port=port,
            default_host=host,
        )
    finally:
        try:
            tls.close()
        except OSError:
            pass


def _handle_exchange(
    sock: socket.socket,
    reader: _Reader,
    message: _Message,
    method: str,
    target: str,
    version: str,
    settings: Settings,
    *,
    scheme: str | None,
    default_port: int | None,
    default_host: str = "",
) -> None:
    located = _locate(target, scheme, default_host, default_port)
    if located is None:
        _send_status(sock, 400, "Bad request")
        return
    url_scheme, host, port, path = located
    mode, length = _body_mode(message.headers)
    if mode == "length" and length > settings.forward_limit:
        raise _TooLarge()
    body = _read_request_body(reader, mode, length, settings.forward_limit)
    wire = _rebuild_request(method, path, version, message.headers, body, host, port)
    try:
        response = _fetch(host, port, url_scheme, wire, settings)
    except (OSError, _Bad, _TooLarge, ssl.SSLError):
        _send_status(sock, 502, "Upstream failed")
        return
    if not allowed(host):
        _emit(format_skip(host, _row_color(settings)))
        sock.sendall(response)
        return
    status, headers, full_body = _split_response(response)
    note = "truncated" if len(body) > settings.max_body or len(full_body) > settings.max_body else ""
    saved_request = _rebuild_request(method, path, version, message.headers, body[: settings.max_body], host, port)
    saved_response = _rebuild_response(status, headers, full_body[: settings.max_body])
    name = _store(saved_request, saved_response, _public_url(url_scheme, host, port, path), host)
    _emit(
        format_row(
            method.upper(),
            _status_code(status),
            len(full_body),
            host,
            path,
            _row_color(settings),
            name=name,
            note=note,
        )
    )
    sock.sendall(response)


def _tunnel(conn: socket.socket, host: str, port: int, settings: Settings) -> None:
    try:
        remote = socket.create_connection((host, port), settings.timeout)
    except OSError:
        _send_status(conn, 502, "Upstream failed")
        return
    _emit(format_tunnel(host, port, _row_color(settings)))
    conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    remote.settimeout(settings.timeout)
    _splice(conn, remote, settings.timeout)
    try:
        remote.close()
    except OSError:
        pass


def _fetch(host: str, port: int, scheme: str, payload: bytes, settings: Settings) -> bytes:
    raw = socket.create_connection((host, port), settings.timeout)
    raw.settimeout(settings.timeout)
    sock: socket.socket = raw
    try:
        if scheme == "https":
            sock = _client_tls(raw, host, settings.insecure)
            sock.settimeout(settings.timeout)
        sock.sendall(payload)
        reader = _Reader(sock)
        message = _parse_head(reader.read_head())
        if message is None:
            raise _Bad()
        mode, length = _body_mode(message.headers)
        if _no_response_body(message.line):
            body = b""
        elif mode == "chunked":
            body = _read_chunked(reader, settings.forward_limit)
        elif mode == "length":
            if length > settings.forward_limit:
                raise _TooLarge()
            body = reader.read_exact(length)
        else:
            body = reader.read_rest(settings.forward_limit)
            if len(body) >= settings.forward_limit:
                raise _TooLarge()
        return _rebuild_response(message.line, message.headers, body)
    finally:
        if sock is not raw:
            try:
                sock.close()
            except OSError:
                pass
        try:
            raw.close()
        except OSError:
            pass


def _store(request: bytes, response: bytes, url: str, host: str) -> str:
    with _LOCK:
        folder = requests_dir()
        folder.mkdir(parents=True, exist_ok=True)
        saved = responses_dir()
        saved.mkdir(parents=True, exist_ok=True)
        name = _capture_name(host)
        (folder / name).write_bytes(request)
        (saved / name).write_bytes(response)
        _remember_url(url)
    return name


def _capture_name(host: str) -> str:
    """example.com-snare-0001.http. The count is per host and shared by both folders."""
    safe = _file_host(host)
    pattern = re.compile(rf"^{re.escape(safe)}-snare-(\d+)\.http$")
    highest = 0
    for folder in (requests_dir(), responses_dir()):
        if not folder.is_dir():
            continue
        for path in folder.iterdir():
            match = pattern.fullmatch(path.name)
            if match:
                highest = max(highest, int(match.group(1)))
    number = highest + 1
    if number > 100000:
        raise _Bad()
    return f"{safe}-snare-{number:04d}.http"


def _file_host(host: str) -> str:
    text = host.lower().rstrip(".").replace(":", "_")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", text).strip("._")
    return (cleaned or "host")[:200]


def _remember_url(url: str) -> None:
    path = urls_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    current = []
    if path.is_file():
        current = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]
    if url in current:
        return
    with path.open("a", encoding="utf-8") as handle:
        handle.write(url + "\n")


def _rebuild_request(
    method: str,
    path: str,
    version: str,
    headers: list[tuple[str, str]],
    body: bytes,
    host: str,
    port: int,
) -> bytes:
    lines = [f"{method} {path} {version}"]
    hop = _hop_names(headers)
    saw_host = False
    saw_encoding = False
    for name, value in headers:
        key = name.lower()
        if key in hop or key == "content-length":
            continue
        if key == "host":
            saw_host = True
        if key == "accept-encoding":
            lines.append(f"{name}: identity")
            saw_encoding = True
            continue
        lines.append(f"{name}: {value}")
    if not saw_host:
        lines.append(f"Host: {_host_header(host, port)}")
    if not saw_encoding:
        lines.append("Accept-Encoding: identity")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace") + body


def _rebuild_response(status: str, headers: list[tuple[str, str]], body: bytes) -> bytes:
    lines = [status]
    hop = _hop_names(headers)
    for name, value in headers:
        key = name.lower()
        if key in hop or key in {"content-length", "transfer-encoding"}:
            continue
        lines.append(f"{name}: {value}")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace") + body


def _read_request_body(reader: _Reader, mode: str, length: int, limit: int) -> bytes:
    if mode == "chunked":
        return _read_chunked(reader, limit)
    if mode == "length":
        return reader.read_exact(length)
    return b""


def _read_chunked(reader: _Reader, limit: int) -> bytes:
    parts: list[bytes] = []
    total = 0
    while True:
        line = reader.read_line()
        token = line.split(b";", 1)[0].strip()
        try:
            size = int(token or b"0", 16)
        except ValueError as exc:
            raise _Bad() from exc
        if size < 0:
            raise _Bad()
        if size == 0:
            while reader.read_line() != b"":
                continue
            return b"".join(parts)
        if total + size > limit:
            raise _TooLarge()
        parts.append(reader.read_exact(size))
        total += size
        reader.read_exact(2)


def _split_response(data: bytes) -> tuple[str, list[tuple[str, str]], bytes]:
    marker = b"\r\n\r\n" if b"\r\n\r\n" in data else b"\n\n"
    head, body = data.split(marker, 1)
    message = _parse_head(head)
    if message is None:
        raise _Bad()
    return message.line, message.headers, body


def _parse_head(head: bytes) -> _Message | None:
    text = head.decode("latin-1", "replace").strip()
    if not text:
        return None
    lines = text.splitlines()
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return _Message(lines[0].strip(), headers)


def _request_parts(line: str) -> tuple[str, str, str] | None:
    parts = line.split()
    if len(parts) < 2 or parts[0].upper().startswith("HTTP/"):
        return None
    version = parts[2] if len(parts) >= 3 else "HTTP/1.1"
    return parts[0], parts[1], version


def _locate(
    target: str,
    scheme: str | None,
    default_host: str,
    default_port: int | None,
) -> tuple[str, str, int, str] | None:
    if "://" in target:
        parts = urlsplit(target)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        return parts.scheme, parts.hostname.lower().rstrip("."), port, path
    host = default_host
    port = default_port
    path = target or "/"
    if not host:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme or "http", host.lower().rstrip("."), port, path


def _public_url(scheme: str, host: str, port: int, path: str) -> str:
    default = 443 if scheme == "https" else 80
    name = f"[{host}]" if ":" in host else host
    netloc = name if port == default else f"{name}:{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{netloc}{path}"


def _body_mode(headers: list[tuple[str, str]]) -> tuple[str, int]:
    encoding = _header(headers, "transfer-encoding").lower()
    if "chunked" in encoding:
        return "chunked", 0
    length = _header(headers, "content-length").split(",")[0].strip()
    if not length:
        return "none", 0
    if not length.isdigit():
        raise _Bad()
    return "length", int(length)


def _no_response_body(status: str) -> bool:
    parts = status.split()
    if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
        return False
    code = parts[1]
    return code in {"204", "304"} or code.startswith("1")


def _status_code(status: str) -> str:
    parts = status.split()
    if len(parts) >= 2 and parts[0].upper().startswith("HTTP/"):
        return parts[1]
    return status


def _header(headers: list[tuple[str, str]], name: str) -> str:
    for key, value in headers:
        if key.lower() == name:
            return value
    return ""


def _hop_names(headers: list[tuple[str, str]]) -> set[str]:
    names = set(_HOP)
    for item in _header(headers, "connection").split(","):
        token = item.strip().lower()
        if token:
            names.add(token)
    return names


def _host_header(host: str, port: int) -> str:
    name = f"[{host}]" if ":" in host else host
    if port in {80, 443}:
        return name
    return f"{name}:{port}"


def _split_authority(value: str) -> tuple[str, int | None]:
    text = value.strip()
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return "", None
        host = text[1:end]
        rest = text[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, None
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
        return host, None
    return text, None


def _client_tls(sock: socket.socket, host: str, insecure: bool) -> ssl.SSLSocket:
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context.wrap_socket(sock, server_hostname=host or None)


def _splice(left: socket.socket, right: socket.socket, timeout: float) -> None:
    def copy(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threads = [
        threading.Thread(target=copy, args=(left, right), daemon=True),
        threading.Thread(target=copy, args=(right, left), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout)


def _send_status(sock: socket.socket, code: int, reason: str) -> None:
    body = reason.encode("ascii", "replace")
    head = f"HTTP/1.1 {code} {reason}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    try:
        sock.sendall(head.encode("ascii") + body)
    except OSError:
        pass


def _openssl(args: list[str], cwd: Path) -> None:
    try:
        done = subprocess.run(
            ["openssl", *args],
            cwd=cwd,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise CaError("openssl is not on PATH.") from exc
    except subprocess.TimeoutExpired as exc:
        raise CaError("openssl took too long.") from exc
    if done.returncode != 0:
        lines = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise CaError(lines[-1] if lines else "openssl failed.")


def _snare_dir() -> Path:
    return workspace_dir() / "snare"


def _loopback_peer(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _row_color(settings: Settings) -> bool:
    return _color(sys.stdout) and not settings.plain


def _status_color(status: str) -> str:
    if status.startswith("2"):
        return _GREEN
    if status.startswith("3"):
        return _CYAN
    if status.startswith("4"):
        return _YELLOW
    if status.startswith("5"):
        return _RED
    return _WHITE


def _banner(art: tuple[str, ...], mark: str, tag: str, color: bool) -> str:
    lines: list[str] = []
    for line in art:
        if not color:
            lines.append(line)
            continue
        if mark in line:
            left, _, right = line.partition(mark)
            lines.append(f"{_CYAN}{left}{_MAGENTA}{mark}{_CYAN}{right}{_RESET}")
            continue
        painted: list[str] = []
        for ch in line:
            if ch in "()[]":
                painted.append(f"{_YELLOW}{ch}{_CYAN}")
            else:
                painted.append(ch)
        lines.append(f"{_CYAN}{''.join(painted)}{_RESET}")
    lines.append(f"{_DIM}{tag}{_RESET}" if color else tag)
    return "\n".join(lines)


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
    print(message, file=sys.stderr, flush=True)


def _emit(line: str) -> None:
    """Print a live row. The console hook redraws the prompt around it."""
    hook = _redraw
    with _print_lock:
        if hook is None:
            print(line, flush=True)
            return
        hook(line)


def _emit_guide(plain: bool) -> None:
    text = format_guide(_color(sys.stderr) and not plain)
    for line in text.splitlines():
        _say(line)


def _display(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()
