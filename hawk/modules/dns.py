"""Look up DNS records for one in-scope name.

One UDP query each for A, AAAA, CNAME, MX, TXT, and NS. There is no zone
transfer and no second query to chase a CNAME. The resolver is the one you
pass, or the first address in the system resolver list.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import socket
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from hawk.workspace import allowed, explain_block

RECORD_TYPES = (
    ("A", 1),
    ("AAAA", 28),
    ("CNAME", 5),
    ("MX", 15),
    ("TXT", 16),
    ("NS", 2),
)
_TYPE_NAMES = {code: label for label, code in RECORD_TYPES}
_MAX_BYTES = 4096


@dataclass
class Question:
    name: str
    qtype: int
    qclass: int


@dataclass
class Record:
    name: str
    rtype: int
    rclass: int
    ttl: int
    text: str


@dataclass
class Message:
    ident: int
    flags: int
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authorities: list[Record] = field(default_factory=list)
    additionals: list[Record] = field(default_factory=list)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk dns",
        description="Look up A, AAAA, CNAME, MX, TXT, and NS for one in-scope name.",
    )
    parser.add_argument("name", help="Hostname to look up. A URL uses that URL's hostname.")
    parser.add_argument("--resolver", help="Resolver address. Default: the first system nameserver.")
    parser.add_argument("--port", type=int, default=53, help="Resolver port. Default 53.")
    parser.add_argument("--timeout", type=float, default=5.0, help="Seconds to wait for each reply. Default 5.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0 or not 1 <= args.port <= 65535:
        _say("Timeout must be greater than 0, and the port must be 1 through 65535.")
        return 2
    name = normalize_name(args.name)
    if not name:
        _say("Give a hostname, such as app.internal.")
        return 2
    if not allowed(name):
        _say(explain_block(name))
        return 2
    if args.resolver:
        resolver = resolver_address(args.resolver)
        if not resolver:
            _say("Pass a resolver address, such as 127.0.0.1.")
            return 2
    else:
        resolver = system_resolver()
        if not resolver:
            _say("No resolver is set. Pass --resolver with an address.")
            return 1
    try:
        found, notes, failed = lookup(name, resolver, args.port, args.timeout)
    except ValueError as exc:
        _say(str(exc))
        return 1
    except OSError as exc:
        _say(f"Could not look up {name}: {exc.__class__.__name__}")
        return 1
    printed = False
    for label, _code in RECORD_TYPES:
        for value in found[label]:
            print(f"{label}\t{value}")
            printed = True
    for note in notes:
        _say(note)
    if failed and not printed:
        _say(f"{name} lookup failed.")
        return 1
    if not printed:
        _say("no records")
    return 0


def lookup(name: str, resolver: str, port: int, timeout: float) -> tuple[dict[str, list[str]], list[str], bool]:
    """Query each record type once. Returns values, notes, and whether a query failed."""
    found = {label: [] for label, _code in RECORD_TYPES}
    notes: list[str] = []
    truncated = False
    failed = False
    family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        for _label, qtype in RECORD_TYPES:
            ident = random.randrange(0, 65536)
            query = build_query(name, qtype, ident)
            data = b""
            for attempt in range(2):
                sock.sendto(query, (resolver, port))
                try:
                    data, _addr = sock.recvfrom(_MAX_BYTES)
                    break
                except socket.timeout:
                    if attempt == 1:
                        raise
            message = parse_message(data)
            if message.ident != ident:
                raise ValueError("response id did not match")
            if message.flags & 0x0200:
                truncated = True
            rcode = message.flags & 0x000F
            if rcode == 2:
                failed = True
                continue
            if rcode not in (0, 3):
                failed = True
                continue
            records = (*message.answers, *message.authorities, *message.additionals)
            for record in records:
                label = _TYPE_NAMES.get(record.rtype)
                if label and record.text and record.text not in found[label]:
                    found[label].append(record.text)
    finally:
        sock.close()
    if truncated:
        notes.append("The answer was truncated.")
    if found["CNAME"] and not found["A"] and not found["AAAA"]:
        notes.append(f"review: CNAME {found['CNAME'][0]} has no address in this answer")
    return found, notes, failed


def encode_name(name: str) -> bytes:
    text = name.strip().strip(".")
    if not text:
        raise ValueError("empty name")
    out = bytearray()
    for label in text.split("."):
        if not label:
            raise ValueError("bad name")
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError:
            raw = label.encode("idna")
        if not raw or len(raw) > 63:
            raise ValueError("bad name")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    if len(out) > 255:
        raise ValueError("name is too long")
    return bytes(out)


def build_query(name: str, qtype: int, ident: int) -> bytes:
    if not 0 <= ident <= 65535:
        raise ValueError("query id is out of range")
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack("!HH", qtype, 1)


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    consumed: int | None = None
    hops = 0
    while True:
        if cursor >= len(data):
            raise ValueError("dns name was truncated")
        length = data[cursor]
        if length == 0:
            cursor += 1
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise ValueError("dns name was truncated")
            if hops > 16:
                raise ValueError("dns name pointer loop")
            hops += 1
            pointer = ((length & 0x3F) << 8) | data[cursor + 1]
            if consumed is None:
                consumed = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            raise ValueError("dns name is not a hostname")
        cursor += 1
        if cursor + length > len(data):
            raise ValueError("dns name was truncated")
        labels.append(data[cursor : cursor + length].decode("ascii", "replace"))
        cursor += length
    end = consumed if consumed is not None else cursor
    return ".".join(labels), end


def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise ValueError("dns message was truncated")
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if qd > 8 or an + ns + ar > 128:
        raise ValueError("dns message is too large")
    offset = 12
    questions: list[Question] = []
    for _ in range(qd):
        name, offset = read_name(data, offset)
        if offset + 4 > len(data):
            raise ValueError("dns question was truncated")
        qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
        offset += 4
        questions.append(Question(name, qtype, qclass))
    answers, offset = _read_rrs(data, offset, an)
    authorities, offset = _read_rrs(data, offset, ns)
    additionals, _offset = _read_rrs(data, offset, ar)
    return Message(ident, flags, questions, answers, authorities, additionals)


def answer_packet(
    query: bytes,
    records: list[tuple[int, bytes]],
    *,
    rcode: int = 0,
    tc: bool = False,
    ident: int | None = None,
) -> bytes:
    """Build a reply for `query`. Records whose type matches the question are included."""
    message = parse_message(query)
    if not message.questions:
        raise ValueError("query has no question")
    question = message.questions[0]
    chosen = [item for item in records if item[0] == question.qtype]
    flags = 0x8180 | (0x0200 if tc else 0) | (rcode & 0xF)
    encoded = encode_name(question.name) + struct.pack("!HH", question.qtype, question.qclass)
    answers = b""
    for rtype, rdata in chosen:
        answers += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    header = struct.pack(
        "!HHHHHH",
        message.ident if ident is None else ident,
        flags,
        1,
        len(chosen),
        0,
        0,
    )
    return header + encoded + answers


def system_resolver() -> str | None:
    try:
        text = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for raw in text.splitlines():
        parts = raw.split("#", 1)[0].split()
        if len(parts) >= 2 and parts[0].lower() == "nameserver":
            address = resolver_address(parts[1])
            if address:
                return address
    return None


def resolver_address(value: str) -> str | None:
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def normalize_name(value: str) -> str | None:
    text = value.strip()
    if "://" in text:
        host = urlsplit(text).hostname or ""
    else:
        host = text
    host = host.lower().rstrip(".")
    if not host or any(char.isspace() for char in host):
        return None
    if any(char in host for char in "*/\\"):
        return None
    if _is_ip(host) or ":" in host:
        return None
    return host


def _read_rrs(data: bytes, offset: int, count: int) -> tuple[list[Record], int]:
    records: list[Record] = []
    for _ in range(count):
        name, offset = read_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError("dns record was truncated")
        rtype, rclass, ttl, length = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + length > len(data):
            raise ValueError("dns record was truncated")
        text = _format_rdata(rtype, data, offset, length)
        records.append(Record(name, rtype, rclass, ttl, text))
        offset += length
    return records, offset


def _format_rdata(rtype: int, packet: bytes, start: int, length: int) -> str:
    blob = packet[start : start + length]
    if rtype == 1 and length == 4:
        return socket.inet_ntoa(blob)
    if rtype == 28 and length == 16:
        return str(ipaddress.IPv6Address(blob))
    if rtype in (2, 5):
        name, _end = read_name(packet, start)
        return name
    if rtype == 15 and length >= 3:
        preference = struct.unpack("!H", blob[:2])[0]
        name, _end = read_name(packet, start + 2)
        return f"{preference} {name}"
    if rtype == 16:
        texts: list[str] = []
        index = 0
        while index < length:
            size = blob[index]
            index += 1
            texts.append(blob[index : index + size].decode("utf-8", "replace"))
            index += size
        return "".join(texts)
    return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _say(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
