"""Read the certificate presented by one in-scope host.

One TLS handshake. The output is the subject, subject alternative names,
issuer, and the validity dates. The chain is not required to be public.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
import sys
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from hawk.workspace import allowed, explain_block, hostname_of

_ATTR = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
}


@dataclass
class Certificate:
    subject: str
    issuer: str
    not_before: str
    not_after: str
    names: list[str] = field(default_factory=list)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk cert",
        description="Read the TLS certificate on one in-scope host.",
    )
    parser.add_argument("host", help="Hostname, address, or https URL.")
    parser.add_argument("--port", type=int, default=0, help="TLS port. Default 443, or the port in the URL.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Seconds to wait for the handshake. Default 10.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0 or args.port < 0 or args.port > 65535:
        _say("Timeout must be greater than 0, and the port must be 0 through 65535.")
        return 2
    host, port = _endpoint(args.host, args.port)
    if not host or port is None:
        _say("Give a hostname or an https URL, such as 127.0.0.1 or https://127.0.0.1:8443.")
        return 2
    if not allowed(host):
        _say(explain_block(hostname_of(host) or host))
        return 2
    try:
        der = fetch_certificate(host, port, args.timeout)
        cert = parse_certificate(der)
    except TimeoutError:
        _say(f"Could not connect to {host}:{port}: timed out.")
        return 1
    except OSError as exc:
        _say(f"Could not connect to {host}:{port}: {exc.__class__.__name__}")
        return 1
    except ValueError as exc:
        _say(f"Could not read the certificate: {exc}")
        return 1
    print(f"subject: {cert.subject}")
    print(f"issuer: {cert.issuer}")
    print(f"not before: {cert.not_before}")
    print(f"not after: {cert.not_after}")
    for name in cert.names:
        print(f"san: {name}")
    return 0


def fetch_certificate(host: str, port: int, timeout: float) -> bytes:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    server_name = None if _is_ip(host) else host
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=server_name) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError("the server presented no certificate")
    return der


def parse_certificate(der: bytes) -> Certificate:
    """Read subject, issuer, dates, and subject alternative names from a DER certificate."""
    _tag, certificate, _end = _tlv(der, 0)
    fields = _items(certificate)
    if not fields or fields[0][0] != 0x30:
        raise ValueError("not a certificate")
    body = _items(fields[0][1])
    if body and body[0][0] == 0xA0:
        body = body[1:]
    if len(body) < 6:
        raise ValueError("certificate is missing the subject")
    issuer = _format_name(body[2][1])
    not_before, not_after = _validity(body[3][1])
    subject = _format_name(body[4][1])
    names = _alt_names(body[6:])
    return Certificate(subject, issuer, not_before, not_after, names)


def _endpoint(value: str, port_arg: int) -> tuple[str, int | None]:
    text = value.strip()
    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return "", None
        port = port_arg or parts.port or (443 if parts.scheme == "https" else None)
        if parts.scheme == "http" and not port_arg and not parts.port:
            return "", None
        return parts.hostname.lower().rstrip("."), port
    if text.startswith("[") and "]" in text:
        host = text[1 : text.index("]")].lower()
        rest = text[text.index("]") + 1 :]
        port = port_arg or (int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 443)
        return host, port
    if text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit():
        host, raw_port = text.rsplit(":", 1)
        return host.lower().rstrip("."), port_arg or int(raw_port)
    return text.lower().rstrip("."), port_arg or 443


def _alt_names(items: list[tuple[int, bytes]]) -> list[str]:
    names: list[str] = []
    for tag, value in items:
        if tag != 0xA3:
            continue
        extensions = _items(value)
        for _ext_tag, ext in extensions:
            parts = _items_raw(ext) if _ext_tag == 0x30 else _items(ext)
            oid = ""
            payload = b""
            for part_tag, part in parts:
                if part_tag == 0x06:
                    oid = _oid(part)
                elif part_tag == 0x04:
                    payload = part
            if oid != "2.5.29.17" or not payload:
                continue
            general = _items(payload) if payload[0] == 0x30 else [(payload[0], payload[1:])]
            if len(general) == 1 and general[0][0] == 0x30:
                general = _items(general[0][1])
            for name_tag, name in general:
                if name_tag == 0x82:
                    names.append("DNS:" + name.decode("ascii", "replace"))
                elif name_tag == 0x87:
                    try:
                        names.append("IP:" + str(ipaddress.ip_address(name)))
                    except ValueError:
                        continue
    return names


def _validity(data: bytes) -> tuple[str, str]:
    times = _items(data)
    if len(times) < 2:
        raise ValueError("certificate has no dates")
    return _time(times[0][1]), _time(times[1][1])


def _format_name(data: bytes) -> str:
    parts: list[str] = []
    for tag, rdn in _items_raw(data):
        if tag != 0x31:
            continue
        for attr_tag, attr in _items_raw(rdn):
            if attr_tag != 0x30:
                continue
            pair = _items_raw(attr)
            if len(pair) < 2 or pair[0][0] != 0x06:
                continue
            label = _ATTR.get(_oid(pair[0][1]), _oid(pair[0][1]))
            parts.append(f"{label}={_string(pair[1][0], pair[1][1])}")
    return ", ".join(parts)


def _string(tag: int, data: bytes) -> str:
    if tag == 0x1E:
        return data.decode("utf-16-be", "replace")
    if tag == 0x1C:
        return data.decode("utf-32-be", "replace")
    return data.decode("utf-8", "replace")


def _time(data: bytes) -> str:
    text = data.decode("ascii", "replace").strip("Z")
    if len(text) >= 14 and text[:4].isdigit():
        year, month, day, hour, minute, second = text[:4], text[4:6], text[6:8], text[8:10], text[10:12], text[12:14]
    elif len(text) >= 12:
        year_num = int(text[:2])
        year = str(1900 + year_num if year_num >= 50 else 2000 + year_num)
        month, day, hour, minute, second = text[2:4], text[4:6], text[6:8], text[8:10], text[10:12]
    else:
        return data.decode("ascii", "replace")
    return f"{year}-{month}-{day} {hour}:{minute}:{second}Z"


def _oid(data: bytes) -> str:
    if not data:
        return ""
    parts = [str(data[0] // 40), str(data[0] % 40)]
    value = 0
    for byte in data[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _items(data: bytes) -> list[tuple[int, bytes]]:
    if not data:
        return []
    tag, value, end = _tlv(data, 0)
    if tag == 0x30 and end == len(data):
        return _items_raw(value)
    return _items_raw(data)


def _items_raw(data: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    index = 0
    while index < len(data):
        tag, value, index = _tlv(data, index)
        items.append((tag, value))
    return items


def _tlv(data: bytes, index: int) -> tuple[int, bytes, int]:
    if index >= len(data):
        raise ValueError("certificate was truncated")
    tag = data[index]
    index += 1
    if index >= len(data):
        raise ValueError("certificate was truncated")
    first = data[index]
    index += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 3 or index + count > len(data):
            raise ValueError("certificate was truncated")
        length = int.from_bytes(data[index : index + count], "big")
        index += count
    else:
        length = first
    end = index + length
    if end > len(data):
        raise ValueError("certificate was truncated")
    return tag, data[index:end], end


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
