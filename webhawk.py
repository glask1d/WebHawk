#!/usr/bin/env python3
"""
WebHawk — HTTP/HTTPS attack-surface mapper
==========================================
Find ports that speak HTTP or HTTPS on hosts you own or have explicit
permission to test. Conservative defaults (common web ports). Full-range
and large-CIDR sweeps require --authorized.

`main` is the toolkit shell. With no subcommand, arguments are a scan.
`scan_main` is that scan, used by the shell and by http_port_probe.py.

Requires: Python 3.10+, rich, httpx
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import ipaddress
import json
import random
import re
import socket
import ssl
import sys
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from hawk import VERSION

THEME = Theme(
    {
        "ok": "bold green",
        "warn": "bold yellow",
        "err": "bold red",
        "info": "bold cyan",
        "muted": "dim",
        "brand": "bold bright_magenta",
        "title": "bold magenta",
        "http": "bold bright_blue",
        "https": "bold bright_green",
        "open": "bold green",
        "closed": "dim",
        "redir": "bold yellow",
        "client": "bold cyan",
        "server": "bold red",
        "port": "bold white",
        "tag": "bold bright_yellow",
        "cert": "bold bright_cyan",
        "crit": "bold bright_red",
        "high": "bold red",
        "med": "bold yellow",
        "low": "bold green",
    }
)

console = Console(theme=THEME, highlight=False)

COMMON_WEB_PORTS = [
    80, 81, 443, 591, 2082, 2083, 2086, 2087, 2095, 2096,
    3000, 3001, 3443, 4000, 4172, 4443, 4567, 5000, 5001,
    5443, 5601, 6000, 6443, 7000, 7001, 7443, 8000, 8001,
    8008, 8010, 8080, 8081, 8088, 8181, 8443, 8484, 8880,
    8888, 9000, 9001, 9090, 9091, 9200, 9443, 10000, 10443,
    12443, 15672, 18080, 28080,
]

USER_AGENTS = [
    "WebHawk/2.3 (+authorized surface mapping)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Opera/9.23 (Nintendo Wii; U; ; 1038-58; Wii Internet Channel/1.0; en)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; PalmSource/hspr-H102; Blazer/4.0) 16;320x320 [ip:127.0.0.1]",
    "Mozilla/1.22 (compatible; MSIE 5.01; PalmOS 3.0) EudoraWeb 2.1",
    "Mozilla/4.0 (PSP (PlayStation Portable); 2.00)",
    "Mozilla/5.0 (X11; GNU/Linux) AppleWebKit/537.36 (KHTML, like Gecko) Chromium/88.0.4324.150 Chrome/88.0.4324.150 Safari/537.36 Tesla/DEV-BUILD-c9db6a2e2678",
    "Mozilla/5.0 (Nintendo Switch; WifiWebAuthApplet) AppleWebKit/601.6 (KHTML, like Gecko) NF/4.0.0.8.9 NintendoBrowser/5.1.0.16739",
    "WebHawk/2.3 (coffee-powered; pecks certificates for sport)",
    "NCSA_Mosaic/2.0 (Windows 3.1)",
    "CERN-LineMode/2.15 libwww/2.17",
    "Lynx/2.8.9rel.1 libwww-FM/2.14 SSL-MM/1.4.1",
    "w3m/0.5.3+git20230121",
    "Links (2.29; Linux 6.8.0 x86_64; GNU C 13.2; text)",
    "IBrowse/2.4 (AmigaOS 3.9; 68k)",
    "HotJava/1.0",
    "Mozilla/3.0 (compatible; WebTV/1.2; processed by a satellite and a prayer)",
    "Mozilla/4.0 (compatible; MSN 6.1; MSN 6.2; Windows XP)",
    "Opera/9.80 (Nintendo 3DS; Opera Mini/7.1; U; en) Presto/2.8.119",
    "Mozilla/5.0 (PlayStation 4 5.05) AppleWebKit/537.73 (KHTML, like Gecko)",
    "Mozilla/5.0 (compatible; Nintendobrowser/0.1; Dreamcast VMU)",
    "Wget/1.21.4 (redacted lab box)",
    "curl/7.88.1 (still waiting for the 90s to end)",
    "Mozilla/5.0 (X11; Linux i686) Gecko/20050511 Firefox/1.0.4 (Debian)",
    "BlackBerry8330/4.3.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/105",
    "DoCoMo/2.0 N905i(c100;TB;W24H16) (compatible; Googlebot-Mobile/2.1; lab-only)",
    "Mozilla/4.0 (compatible; Dillo 3.0)",
    "Surf/2.1 (X11; Linux x86_64) WebHawk-edition",
    "Mozilla/5.0 (Macintosh; PPC Mac OS X; U; en) AppleWebKit/125.5 (KHTML, like Gecko) Safari/85",
    "Python-urllib/1.17",
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
MAX_BODY_SNIPPET = 180
MAX_CIDR_HOSTS_SOFT = 256
MAX_CIDR_HOSTS_HARD = 1024
HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}

PANEL_SIGNATURES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"grafana", re.I), "grafana"),
    (re.compile(r"kibana", re.I), "kibana"),
    (re.compile(r"jenkins", re.I), "jenkins"),
    (re.compile(r"phpmyadmin", re.I), "phpmyadmin"),
    (re.compile(r"tomcat", re.I), "tomcat"),
    (re.compile(r"weblogic", re.I), "weblogic"),
    (re.compile(r"webmin", re.I), "webmin"),
    (re.compile(r"prometheus", re.I), "prometheus"),
    (re.compile(r"portainer", re.I), "portainer"),
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"apache", re.I), "apache"),
    (re.compile(r"iis |microsoft-iis|iis windows", re.I), "iis"),
    (re.compile(r"caddy", re.I), "caddy"),
    (re.compile(r"traefik", re.I), "traefik"),
    (re.compile(r"minio", re.I), "minio"),
    (re.compile(r"rabbitmq", re.I), "rabbitmq"),
    (re.compile(r"couchdb", re.I), "couchdb"),
    (re.compile(r"elasticsearch", re.I), "elasticsearch"),
    (re.compile(r"sonarqube", re.I), "sonarqube"),
    (re.compile(r"gitlab", re.I), "gitlab"),
    (re.compile(r"nextcloud", re.I), "nextcloud"),
    (re.compile(r"wordpress", re.I), "wordpress"),
    (re.compile(r"drupal", re.I), "drupal"),
]

PATH_MUTATIONS = [
    ".bak", ".old", ".orig", ".tmp", ".temp", ".copy", ".bak1",
    ".zip", ".tar", ".tar.gz", ".tgz", ".7z", ".rar",
    ".sql", ".sql.gz", ".log", ".swp", ".swo", "~",
]

ARTIFACT_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.hg/requires",
    "/.env",
    "/.env.local",
    "/.htpasswd",
    "/.htaccess",
    "/.DS_Store",
    "/web.config",
    "/crossdomain.xml",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/backup.zip",
    "/backup.tar.gz",
    "/dump.sql",
]

COMMON_PARAMS = [
    "debug", "test", "admin", "dev", "staging",
    "redirect", "url", "next", "return", "dest",
    "callback", "jsonp", "api_key", "key", "token",
    "id", "file", "path", "page", "format",
]

ENDPOINT_RE = re.compile(r"\.(php|phtml|asp|aspx|jsp|do|action|cgi)(/|$|\?)", re.I)
API_PATH_RE = re.compile(r"/api(/|$)|/graphql|/rest(/|$)|/v[0-9]+(/|$)", re.I)
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=['\"]([^'\"]+)['\"]", re.I)
JS_URL_RE = re.compile(
    r"""(?:fetch|axios|jQuery\.ajax|\.ajax|\.get|\.post|\.put|\.delete)\s*\(\s*['"]([^'"]+)['"]""",
    re.I,
)
JS_ABS_URL_RE = re.compile(r"""['"]((?:https?:)?//[^'"]+)['"]""")
JS_PATH_RE = re.compile(r"""['"](/[A-Za-z0-9_\-./]{3,120})['"]""")
SECRETISH_RE = re.compile(
    r"""(?i)(api[_-]?key|secret|token|password|auth)\s*[:=]\s*['"]([A-Za-z0-9_\-]{8,})['"]"""
)

FAVICON_HINTS = {
    # Shodan-style mmh3 hashes for common products. Unknown hashes still print.
    "81586312": "Jenkins",
    "2123863676": "Grafana",
    "116323821": "Grafana (alt)",
    "848442153": "Grafana (alt)",
    "1265477436": "GitLab",
    "1278323681": "GitLab (alt)",
    "-235391543": "WordPress",
    "-247388890": "WordPress (alt)",
    "159406847": "WordPress (alt)",
    "-297069493": "Apache Tomcat",
    "1163238210": "Apache HTTP Server",
    "708578229": "Google",
    "-1659512841": "Kibana",
    "1611729805": "Elasticsearch",
    "1722105798": "phpMyAdmin",
    "-471426521": "Webmin",
    "541088007": "Jupyter",
    "-1524558921": "Netdata",
    "-1379982221": "Atlassian Bamboo",
    "667017222": "Bitbucket",
    "-305179312": "Confluence",
    "1369277006": "Crucible",
    "-1665357670": "Fisheye",
    "705143395": "Jira Service Management",
    "628535358": "Jira Software",
    "-1806014473": "Statuspage",
    "-299287097": "Cisco Web UI",
    "-1166125415": "Netscaler Gateway",
    "-82958153": "ScreenConnect",
    "-335242539": "F5 BIG-IP",
    "945408572": "FortiGate",
    "-1028703694": "Fortinet (alt)",
    "467483715": "FortiADC / FortiExtender",
    "905744673": "HP Embedded Web Server",
    "-1912808902": "IBM QRadar SOAR",
    "-600183134": "IBM Guardium",
    "1726027799": "IBM HTTP Server",
    "1725856879": "Imperva Data Security Fabric",
    "-1439222863": "Ivanti Connect Secure",
    "-1944119648": "TeamCity",
    "-1269979934": "Mastodon",
    "1768726119": "Outlook Web App",
    "396533629": "OpenVPN Access Server",
    "-524723557": "Cortex XSOAR",
    "873381299": "Palo Alto Firewall",
    "-631559155": "GlobalProtect Portal",
    "-1142586156": "PaperCut MF",
    "989289239": "MOVEit",
    "213144638": "Proxmox VE",
    "-266008933": "SAP NetWeaver",
    "1701804003": "ServiceNow",
    "631108382": "SonicWall",
    "1601194732": "Sophos",
    "-1441956789": "Tableau Server",
    "45180380": "VMware ESXi",
    "1521142546": "VMware Horizon",
    "892542951": "Zabbix",
    "1624375939": "Zimbra",
    "1205970462": "Zyxel",
    "970132176": "3CX",
    "-123519246": "cPanel",
    "999357577": "Plesk",
    "157004943": "Roundcube",
    "1620829871": "phpLiteAdmin",
    "-1255342600": "Django",
    "1318124266": "Spring Boot",
    "-873627015": "Portainer",
    "1165838194": "Traefik",
    "-206761241": "MinIO",
    "1876585825": "RabbitMQ",
    "-2017602366": "Prometheus",
}

SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS", "medium", "Missing HSTS (HTTPS only)"),
    ("content-security-policy", "CSP", "medium", "Missing Content-Security-Policy"),
    ("x-frame-options", "X-Frame-Options", "low", "Missing X-Frame-Options (clickjacking)"),
    ("x-content-type-options", "X-Content-Type-Options", "low", "Missing X-Content-Type-Options"),
    ("referrer-policy", "Referrer-Policy", "info", "Missing Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy", "info", "Missing Permissions-Policy"),
]


@dataclass
class TlsInfo:
    version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    san: list[str] = field(default_factory=list)
    expired: bool = False
    error: str = ""


@dataclass
class HttpHit:
    scheme: str
    url: str
    final_url: str
    status: int | None
    reason: str
    server: str
    powered_by: str
    content_type: str
    location: str
    title: str
    snippet: str
    bytes_read: int
    sha256: str
    elapsed_ms: float
    tags: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    tls: TlsInfo | None = None
    error: str = ""
    body: bytes = field(default=b"", repr=False)


@dataclass
class PortResult:
    port: int
    tcp_open: bool
    hits: list[HttpHit] = field(default_factory=list)
    tcp_error: str = ""
    banner: str = ""


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    url: str = ""
    evidence: str = ""


@dataclass
class HostReport:
    target: str
    resolved: list[str]
    results: list[PortResult]
    elapsed: float
    findings: list[Finding] = field(default_factory=list)
    dns: dict[str, list[str]] = field(default_factory=dict)
    ct_names: list[str] = field(default_factory=list)
    banners: list[str] = field(default_factory=list)
    js_urls: list[str] = field(default_factory=list)
    favicon_hash: str = ""
    favicon_hint: str = ""


def banner() -> None:
    art = Text()
    art.append("  ██╗    ██╗███████╗██████╗ ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗\n", style="bright_magenta")
    art.append("  ██║    ██║██╔════╝██╔══██╗██║  ██║██╔══██╗██║    ██║██║ ██╔╝\n", style="magenta")
    art.append("  ██║ █╗ ██║█████╗  ██████╔╝███████║███████║██║ █╗ ██║█████╔╝ \n", style="bright_cyan")
    art.append("  ██║███╗██║██╔══╝  ██╔══██╗██╔══██║██╔══██║██║███╗██║██╔═██╗ \n", style="cyan")
    art.append("  ╚███╔███╔╝███████╗██████╔╝██║  ██║██║  ██║╚███╔███╔╝██║  ██╗\n", style="bright_blue")
    art.append("   ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝\n", style="blue")
    art.append(f"   HTTP/HTTPS attack-surface mapper  v{VERSION}\n", style="brand")
    console.print(art)
    console.print(
        Panel.fit(
            "[warn]Authorized use only.[/warn] Scan hosts you own or have written permission to test.\n"
            "[muted]Unauthorized scanning can be illegal. Defaults stay small: common web ports.[/muted]",
            border_style="yellow",
            title="[warn]rules of engagement[/warn]",
        )
    )
    console.print()


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise argparse.ArgumentTypeError("ports must be in 1-65535")
            ports.update(range(start, end + 1))
        else:
            p = int(chunk)
            if p < 1 or p > 65535:
                raise argparse.ArgumentTypeError("ports must be in 1-65535")
            ports.add(p)
    return sorted(ports)


def parse_status_set(spec: str | None) -> set[int] | None:
    if not spec:
        return None
    out: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            out.update(range(int(a), int(b) + 1))
        else:
            out.add(int(chunk))
    return out


def parse_delay_range(spec: str | None) -> tuple[float, float]:
    if not spec:
        return 0.0, 0.0
    text = str(spec).strip()
    if not text:
        return 0.0, 0.0
    if "-" in text:
        left, right = text.split("-", 1)
        lo, hi = float(left), float(right)
    else:
        lo = hi = float(text)
    if lo < 0 or hi < 0:
        raise argparse.ArgumentTypeError("delay cannot be negative")
    if lo > hi:
        lo, hi = hi, lo
    return lo, hi


async def jitter_sleep(lo: float, hi: float) -> None:
    if hi <= 0:
        return
    await asyncio.sleep(random.uniform(lo, hi))


def looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def normalize_host(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.hostname or raw
    host = raw.split("/")[0]
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")]
    return host.split(":")[0]


def normalize_path(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return "/"
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        raw = parsed.path or "/"
        if parsed.query:
            raw = f"{raw}?{parsed.query}"
    if not raw.startswith("/"):
        raw = "/" + raw
    return raw


def expand_cidr(token: str) -> list[str] | None:
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    hosts = [str(h) for h in net.hosts()]
    if not hosts:
        hosts = [str(net.network_address)]
    return hosts


def load_list_file(path: Path) -> list[str]:
    if not path.is_file():
        raise FileNotFoundError(f"list file not found: {path}")
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def load_target_file(path: Path) -> list[str]:
    return load_list_file(path)


def looks_like_existing_file(value: str) -> bool:
    if not value or any(ch in value for ch in (",", "\n", "\r")):
        return False
    # A single header "X-Foo: bar" is not a file. A UA string usually isn't a path
    # that exists. Only treat it as a file when the path actually exists.
    try:
        return Path(value).expanduser().is_file()
    except OSError:
        return False


def refuse_file_targets(targets: list[str]) -> int | None:
    """Warn when a positional target is a file. Stop if every target is one.

    `webhawk targets.txt` used to send the filename through DNS. A list of
    hosts belongs on `-l`. A mix of hosts and files still scans the hosts.
    """
    files = [
        token
        for token in targets
        if token and "://" not in token and not token.startswith("-") and looks_like_existing_file(token)
    ]
    if not files:
        return None
    for token in files:
        console.print(
            f"[warn]{token}[/warn] is a file. Scan the hosts in it with [info]-l {token}[/info]",
            crop=False,
        )
    real_targets = [token for token in targets if token]
    if len(files) == len(real_targets):
        console.print("[err]No hosts were given.[/err]")
        return 2
    return None


def dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def parse_header_line(line: str) -> tuple[str, str]:
    if ":" not in line:
        raise ValueError(f"header must look like 'Name: value' (got {line!r})")
    name, value = line.split(":", 1)
    name, value = name.strip(), value.strip()
    if not name:
        raise ValueError(f"empty header name in {line!r}")
    return name, value


def merge_headers(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, value in pairs:
        out[name] = value
    return out


def collect_custom_headers(header_args: list[str], headers_file: str | None) -> dict[str, str]:
    pairs: list[tuple[str, str]] = []
    for item in header_args:
        if looks_like_existing_file(item):
            for line in load_list_file(Path(item).expanduser()):
                pairs.append(parse_header_line(line))
        else:
            pairs.append(parse_header_line(item))
    if headers_file:
        for line in load_list_file(Path(headers_file).expanduser()):
            pairs.append(parse_header_line(line))
    return merge_headers(pairs)


def collect_user_agents(user_agent: str | None, agents_file: str | None, randomize: bool) -> list[str]:
    agents: list[str] = []
    if user_agent:
        if looks_like_existing_file(user_agent):
            agents.extend(load_list_file(Path(user_agent).expanduser()))
        else:
            agents.append(user_agent)
    if agents_file:
        agents.extend(load_list_file(Path(agents_file).expanduser()))
    agents = [a.strip() for a in agents if a.strip()]
    if not agents:
        agents = list(USER_AGENTS) if randomize else [USER_AGENTS[0]]
    elif randomize and len(agents) == 1 and agents[0] == USER_AGENTS[0]:
        agents = list(USER_AGENTS)
    return dedupe(agents)


def collect_paths(paths_arg: str | None, paths_file: str | None) -> list[str]:
    paths: list[str] = []
    if paths_arg:
        if looks_like_existing_file(paths_arg):
            paths.extend(load_list_file(Path(paths_arg).expanduser()))
        else:
            paths.extend(part.strip() for part in paths_arg.split(",") if part.strip())
    if paths_file:
        paths.extend(load_list_file(Path(paths_file).expanduser()))
    normalized = [normalize_path(p) for p in paths]
    return dedupe(normalized) or ["/"]


def mutate_paths(paths: list[str], extra: list[str] | None = None) -> list[str]:
    suffixes = list(PATH_MUTATIONS)
    if extra:
        for item in extra:
            item = item.strip()
            if not item:
                continue
            if not item.startswith(".") and item != "~":
                item = "." + item
            suffixes.append(item)
    out = list(paths)
    for path in paths:
        if "?" in path or path.endswith("/"):
            continue
        for suffix in suffixes:
            if suffix == "~":
                out.append(path + "~")
            else:
                out.append(path + suffix)
    return dedupe(out)


def looks_like_endpoint(path: str) -> bool:
    return bool(ENDPOINT_RE.search(path) or API_PATH_RE.search(path))


def with_query(path: str, name: str, value: str = "1") -> str:
    parsed = urlparse(path if "://" not in path else f"http://x{path}")
    raw = path
    if "://" in path:
        parsed = urlparse(path)
        q = dict(parse_qsl(parsed.query, keep_blank_values=True))
        q[name] = value
        return urlunparse(parsed._replace(query=urlencode(q)))
    if "?" in raw:
        base, qs = raw.split("?", 1)
        q = dict(parse_qsl(qs, keep_blank_values=True))
        q[name] = value
        return base + "?" + urlencode(q)
    return raw + "?" + urlencode({name: value})


def murmurhash3_32(data: bytes, seed: int = 0) -> int:
    """Signed 32-bit MurmurHash3, matching the Shodan favicon hash convention."""
    length = len(data)
    nblocks = length // 4
    h = seed
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    def u32(x: int) -> int:
        return x & 0xFFFFFFFF

    def rotl(x: int, r: int) -> int:
        return u32((x << r) | (x >> (32 - r)))

    for i in range(nblocks):
        k = int.from_bytes(data[i * 4 : i * 4 + 4], "little")
        k = u32(k * c1)
        k = rotl(k, 15)
        k = u32(k * c2)
        h ^= k
        h = rotl(h, 13)
        h = u32(h * 5 + 0xE6546B64)

    tail = data[nblocks * 4 :]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = u32(k * c1)
        k = rotl(k, 15)
        k = u32(k * c2)
        h ^= k

    h ^= length
    h ^= h >> 16
    h = u32(h * 0x85EBCA6B)
    h ^= h >> 13
    h = u32(h * 0xC2B2AE35)
    h ^= h >> 16
    if h >= 0x80000000:
        return h - 0x100000000
    return h


def shodan_favicon_hash(body: bytes) -> int:
    import base64

    b64 = base64.encodebytes(body)
    return murmurhash3_32(b64)


def header_lookup(headers: dict[str, str], name: str) -> str:
    want = name.lower()
    for key, value in headers.items():
        if key.lower() == want:
            return value
    return ""


def score_security_headers(url: str, headers: dict[str, str], scheme: str) -> list[Finding]:
    findings: list[Finding] = []
    for header, short, severity, missing_msg in SECURITY_HEADERS:
        if header == "strict-transport-security" and scheme != "https":
            continue
        if not header_lookup(headers, header):
            findings.append(Finding(severity, f"Missing {short}", missing_msg, url=url))
    acao = header_lookup(headers, "access-control-allow-origin")
    if acao == "*":
        findings.append(Finding("medium", "CORS allows any origin", "Access-Control-Allow-Origin: *", url=url, evidence=acao))
    hsts = header_lookup(headers, "strict-transport-security")
    if scheme == "https" and hsts:
        age_m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if age_m and int(age_m.group(1)) < 15552000:
            findings.append(
                Finding("low", "Short HSTS max-age", "max-age is under 180 days", url=url, evidence=hsts[:80])
            )
        if "includesubdomains" not in hsts.lower():
            findings.append(Finding("info", "HSTS without includeSubDomains", hsts[:80], url=url))
    findings.extend(score_cookie_flags(url, header_lookup(headers, "set-cookie"), scheme))
    return findings


def score_cookie_flags(url: str, raw: str, scheme: str) -> list[Finding]:
    if not raw:
        return []
    findings: list[Finding] = []
    for cookie in raw.split("\n"):
        cookie = cookie.strip()
        if not cookie or "=" not in cookie:
            continue
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        if scheme == "https" and "secure" not in low:
            findings.append(Finding("medium", f"Cookie '{name}' missing Secure", cookie[:120], url=url, evidence=name))
        if "httponly" not in low:
            findings.append(Finding("low", f"Cookie '{name}' missing HttpOnly", cookie[:120], url=url, evidence=name))
        if "samesite" not in low:
            findings.append(Finding("low", f"Cookie '{name}' missing SameSite", cookie[:120], url=url, evidence=name))
        elif "samesite=none" in low and "secure" not in low:
            findings.append(Finding("medium", f"Cookie '{name}' SameSite=None without Secure", cookie[:120], url=url))
    return findings


def parse_security_txt(url: str, body: bytes, status: int | None) -> list[Finding]:
    findings: list[Finding] = []
    if status is None or status >= 400:
        return findings
    text = body.decode("utf-8", errors="replace")
    fields: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    contact = fields.get("contact") or []
    expires = (fields.get("expires") or [""])[0]
    if contact:
        findings.append(
            Finding("info", "security.txt present", "Contact: " + ", ".join(contact[:4]), url=url, evidence="; ".join(contact[:3]))
        )
    else:
        findings.append(Finding("low", "security.txt missing Contact", "RFC 9116 requires at least one Contact field", url=url))
    if expires:
        try:
            stamp = expires.replace("Z", "+00:00")
            when = datetime.fromisoformat(stamp)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if when < datetime.now(timezone.utc):
                findings.append(Finding("medium", "security.txt expired", f"Expires: {expires}", url=url, evidence=expires))
            else:
                findings.append(Finding("info", "security.txt Expires", expires, url=url))
        except ValueError:
            findings.append(Finding("low", "security.txt Expires not ISO-8601", expires, url=url))
    else:
        findings.append(Finding("low", "security.txt missing Expires", "RFC 9116 recommends an Expires field", url=url))
    for extra in ("encryption", "policy", "canonical", "hiring", "acknowledgments"):
        if extra in fields:
            findings.append(Finding("info", f"security.txt {extra}", ", ".join(fields[extra][:3]), url=url))
    return findings


def extract_js_intel(base_url: str, body: bytes) -> tuple[list[str], list[str], list[Finding]]:
    text = body.decode("utf-8", errors="ignore")
    urls = []
    for match in SCRIPT_SRC_RE.findall(text):
        urls.append(urljoin(base_url, match))
    for match in JS_URL_RE.findall(text):
        urls.append(urljoin(base_url, match))
    for match in JS_ABS_URL_RE.findall(text):
        if match.startswith("//"):
            urls.append("https:" + match)
        else:
            urls.append(match)
    for match in JS_PATH_RE.findall(text):
        if any(tok in match.lower() for tok in ("/api", "/v1", "/v2", "/graphql", "/rest", "/admin")):
            urls.append(urljoin(base_url, match))
    findings: list[Finding] = []
    secrets = []
    for label, value in SECRETISH_RE.findall(text)[:8]:
        secrets.append(f"{label}={value[:6]}…")
        findings.append(
            Finding(
                "high",
                "Possible secret in JavaScript/HTML",
                f"Key-like assignment for '{label}'",
                url=base_url,
                evidence=f"{label}=***",
            )
        )
    return dedupe(urls)[:80], secrets, findings


def resolve_host(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addrs: list[str] = []
    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            addrs.append(addr)
    return addrs


def doh_records(name: str, rtype: str, timeout: float = 6.0) -> list[str]:
    if looks_like_ip(name):
        return []
    url = "https://cloudflare-dns.com/dns-query"
    try:
        resp = httpx.get(
            url,
            params={"name": name, "type": rtype},
            headers={"accept": "application/dns-json"},
            timeout=timeout,
        )
        data = resp.json()
    except Exception:
        return []
    answers = data.get("Answer") or []
    out: list[str] = []
    for item in answers:
        rec = str(item.get("data", "")).strip()
        if rec:
            out.append(rec.strip('"'))
    return out


def enumerate_dns(host: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        recs = doh_records(host, rtype)
        if recs:
            result[rtype] = recs
    dmarc = doh_records(f"_dmarc.{host}", "TXT")
    if dmarc:
        result["DMARC"] = dmarc
    return result


def fetch_ct_names(host: str, limit: int = 80) -> list[str]:
    if looks_like_ip(host):
        return []
    url = "https://crt.sh/"
    try:
        resp = httpx.get(url, params={"q": host, "output": "json"}, timeout=20.0)
        rows = resp.json()
    except Exception:
        return []
    names: list[str] = []
    seen: set[str] = set()
    if not isinstance(rows, list):
        return []
    for row in rows:
        raw = str(row.get("name_value", ""))
        for piece in raw.split("\n"):
            name = piece.strip().lower().lstrip("*.")
            if name and host.split(":")[0].lower() in name and name not in seen:
                seen.add(name)
                names.append(name)
                if len(names) >= limit:
                    return names
    return names


async def banner_grab(host: str, port: int, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception:
        return ""
    payload = b""
    if port in {25, 587, 2525}:
        payload = b"EHLO webhawk.local\r\n"
    elif port in {21}:
        payload = b""
    elif port in {110, 143}:
        payload = b""
    elif port in {6379}:
        payload = b"PING\r\n"
    try:
        if payload:
            writer.write(payload)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
    except Exception:
        data = b""
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    text = data.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ").strip()
    return text[:200]


def status_style(code: int | None) -> str:
    if code is None:
        return "muted"
    if 200 <= code < 300:
        return "ok"
    if 300 <= code < 400:
        return "redir"
    if 400 <= code < 500:
        return "client"
    if 500 <= code < 600:
        return "server"
    return "muted"


def extract_title(html: str) -> str:
    m = TITLE_RE.search(html)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:160]


def snippet_of(body: bytes, content_type: str) -> str:
    text = body.decode("utf-8", errors="replace")
    text = re.sub(r"\s+", " ", text).strip()
    if "html" in content_type.lower() or text.lstrip().startswith("<"):
        stripped = re.sub(r"<script[\s\S]*?</script>", " ", text, flags=re.I)
        stripped = re.sub(r"<style[\s\S]*?</style>", " ", stripped, flags=re.I)
        stripped = re.sub(r"<[^>]+>", " ", stripped)
        stripped = re.sub(r"\s+", " ", stripped).strip()
        text = stripped or text
    return text[:MAX_BODY_SNIPPET]


def classify_tags(status: int | None, title: str, server: str, snippet: str, body: bytes) -> list[str]:
    tags: list[str] = []
    blob = f"{title}\n{server}\n{snippet}\n{body[:2000].decode('utf-8', errors='ignore')}"
    if status == 401:
        tags.append("auth-required")
    if status == 403:
        tags.append("forbidden")
    if status is not None and 300 <= status < 400:
        tags.append("redirect")
    if status is not None and 500 <= status < 600:
        tags.append("server-error")
    low = blob.lower()
    if "index of /" in low or "directory listing" in low:
        tags.append("dir-listing")
    if any(s in low for s in ("welcome to nginx", "apache2 ubuntu default", "iis windows server", "it works!")):
        tags.append("default-page")
    for pattern, name in PANEL_SIGNATURES:
        if pattern.search(blob):
            tags.append(name)
            break
    return tags


def header_map(headers: httpx.Headers) -> dict[str, str]:
    interesting = {
        "server",
        "x-powered-by",
        "x-generator",
        "x-aspnet-version",
        "x-frame-options",
        "content-security-policy",
        "strict-transport-security",
        "www-authenticate",
        "location",
        "via",
        "x-backend-server",
        "x-drupal-cache",
        "x-served-by",
        "cdn-cache-control",
        "allow",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    }
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in interesting or key.lower().startswith("x-"):
            out[key] = value
    cookies = headers.get_list("set-cookie")
    if cookies:
        out["set-cookie"] = "\n".join(cookies)
    return out


def collect_tls(host: str, port: int, timeout: float) -> TlsInfo:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sni = host if not looks_like_ip(host) else None
            with ctx.wrap_socket(sock, server_hostname=sni or host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version() or ""
    except Exception as exc:
        return TlsInfo(error=str(exc)[:160])

    def name_from(entries: object) -> str:
        if not entries:
            return ""
        parts: list[str] = []
        try:
            for item in entries:  # type: ignore[not-iterable]
                if isinstance(item, tuple) and item and isinstance(item[0], tuple):
                    for k, v in item:
                        if k in {"commonName", "organizationName"}:
                            parts.append(f"{k}={v}")
        except TypeError:
            return str(entries)
        return ", ".join(parts)

    san: list[str] = []
    for typ, val in cert.get("subjectAltName", ()) or ():
        san.append(f"{typ}:{val}")
    not_after = cert.get("notAfter", "")
    expired = False
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            expired = expires < datetime.now(timezone.utc)
        except ValueError:
            expired = False
    return TlsInfo(
        version=version,
        cipher=cipher[0] if cipher else "",
        subject=name_from(cert.get("subject")),
        issuer=name_from(cert.get("issuer")),
        not_before=cert.get("notBefore", ""),
        not_after=not_after,
        san=san[:12],
        expired=expired,
    )


async def tcp_probe(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, ""
    except asyncio.TimeoutError:
        return False, "timeout"
    except ConnectionRefusedError:
        return False, "refused"
    except OSError as exc:
        return False, exc.strerror or str(exc)
    except Exception as exc:
        return False, str(exc)


def speaking(hit: HttpHit | None) -> bool:
    if hit is None:
        return False
    if hit.status is not None:
        return True
    err = hit.error.lower()
    if not err:
        return False
    noise = ("timeout", "connect", "refused", "ssl", "eof", "wrong version", "certificate", "handshake")
    return not any(token in err for token in noise)


def hit_passes_filters(
    hit: HttpHit,
    status_allow: set[int] | None,
    grep: re.Pattern[str] | None,
) -> bool:
    if not speaking(hit):
        return False
    if status_allow is not None and (hit.status is None or hit.status not in status_allow):
        return False
    if grep is not None:
        hay = " ".join([hit.title, hit.snippet, hit.server, hit.powered_by, hit.error])
        if not grep.search(hay):
            return False
    return True


def error_hit(scheme: str, url: str, started: float, error: str) -> HttpHit:
    return HttpHit(
        scheme,
        url,
        url,
        None,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        0,
        "",
        (time.perf_counter() - started) * 1000,
        error=error,
    )


async def http_probe(
    client: httpx.AsyncClient,
    method: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    keep_body: bool,
    max_body: int,
    retries: int,
    extra_headers: dict[str, str] | None = None,
) -> HttpHit:
    url = f"{scheme}://{host}:{port}{path}"
    t0 = time.perf_counter()
    last_error = "request failed"
    attempts = max(1, retries + 1)
    for attempt in range(attempts):
        try:
            resp = await client.request(method, url, headers=extra_headers)
            elapsed = (time.perf_counter() - t0) * 1000
            body = resp.content[:max_body]
            ctype = resp.headers.get("content-type", "")
            decoded = body.decode("utf-8", errors="ignore") if body else ""
            title = extract_title(decoded)
            tags = classify_tags(
                resp.status_code,
                title,
                resp.headers.get("server", ""),
                snippet_of(body, ctype),
                body,
            )
            digest = hashlib.sha256(resp.content).hexdigest()[:16] if resp.content else ""
            allow = resp.headers.get("allow", "")
            if method == "OPTIONS" and allow:
                tags.append(f"allow:{allow.replace(' ', '')}")
            return HttpHit(
                scheme=scheme,
                url=url,
                final_url=str(resp.url),
                status=resp.status_code,
                reason=resp.reason_phrase or "",
                server=resp.headers.get("server", ""),
                powered_by=resp.headers.get("x-powered-by", ""),
                content_type=ctype.split(";")[0].strip(),
                location=resp.headers.get("location", ""),
                title=title,
                snippet=snippet_of(body, ctype) if body else "",
                bytes_read=len(resp.content),
                sha256=digest,
                elapsed_ms=elapsed,
                tags=tags,
                headers=header_map(resp.headers),
                body=body if keep_body else b"",
            )
        except httpx.TimeoutException:
            last_error = "timeout"
        except ssl.SSLError as exc:
            last_error = f"ssl: {exc}"
            break
        except httpx.ConnectError as exc:
            last_error = f"connect: {exc}"
        except Exception as exc:
            msg = str(exc)
            last_error = (msg[:157] + "...") if len(msg) > 160 else msg
        if attempt + 1 < attempts:
            await asyncio.sleep(0.15 * (attempt + 1))
    return error_hit(scheme, url, t0, last_error)


def safe_name(host: str, port: int, scheme: str, path: str) -> str:
    path_part = path.strip("/") or "root"
    path_part = re.sub(r"[^A-Za-z0-9._-]+", "_", path_part)[:60]
    host_part = re.sub(r"[^A-Za-z0-9._-]+", "_", host)[:80]
    return f"{host_part}_{port}_{scheme}_{path_part}"


def extension_for(content_type: str, body: bytes) -> str:
    ctype = content_type.lower()
    if "json" in ctype or body.lstrip().startswith(b"{"):
        return ".json"
    if "html" in ctype or body.lstrip()[:32].lower().startswith(b"<!doctype") or b"<html" in body[:400].lower():
        return ".html"
    if "xml" in ctype:
        return ".xml"
    if "javascript" in ctype:
        return ".js"
    if "css" in ctype:
        return ".css"
    if "text/" in ctype:
        return ".txt"
    return ".bin"


class ArtifactSink:
    def __init__(
        self,
        urls_path: Path | None,
        source_dir: Path | None,
        header_dir: Path | None,
    ) -> None:
        self.urls_path = urls_path
        self.source_dir = source_dir
        self.header_dir = header_dir
        self._url_fh = None
        self.seen_urls: set[str] = set()
        if urls_path:
            urls_path.parent.mkdir(parents=True, exist_ok=True)
            self._url_fh = urls_path.open("a", encoding="utf-8")
        if source_dir:
            source_dir.mkdir(parents=True, exist_ok=True)
        if header_dir:
            header_dir.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if self._url_fh:
            self._url_fh.close()
            self._url_fh = None

    def capture(self, host: str, port: int, hit: HttpHit) -> None:
        if not speaking(hit):
            return
        url = hit.final_url or hit.url
        if self._url_fh and url not in self.seen_urls:
            self.seen_urls.add(url)
            self._url_fh.write(url + "\n")
            self._url_fh.flush()
        stem = safe_name(host, port, hit.scheme, urlparse(hit.url).path or "/")
        if self.source_dir and hit.body:
            ext = extension_for(hit.content_type, hit.body)
            (self.source_dir / f"{stem}{ext}").write_bytes(hit.body)
        if self.header_dir:
            lines = [
                f"URL: {hit.url}",
                f"Final-URL: {hit.final_url}",
                f"Status: {hit.status} {hit.reason}".strip(),
                f"SHA256-16: {hit.sha256}",
                "",
            ]
            for k, v in hit.headers.items():
                lines.append(f"{k}: {v}")
            (self.header_dir / f"{stem}.headers.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


async def scan_host(
    target: str,
    ports: list[int],
    connect_timeout: float,
    http_timeout: float,
    concurrency: int,
    paths: list[str],
    follow_redirects: bool,
    try_http: bool,
    try_https: bool,
    verify_tls: bool,
    user_agents: list[str],
    rotate_agent: bool,
    host_header: str | None,
    custom_headers: dict[str, str],
    collect_certs: bool,
    keep_body: bool,
    max_body: int,
    delay_lo: float,
    delay_hi: float,
    proxy: str | None,
    sink: ArtifactSink | None,
    status_allow: set[int] | None,
    grep: re.Pattern[str] | None,
    skip_tcp: bool,
    method: str,
    retries: int,
    auth: httpx.Auth | None,
) -> list[PortResult]:
    if skip_tcp:
        tcp_results = [PortResult(port=p, tcp_open=True) for p in ports]
        console.print(f"[warn]skip-tcp[/warn] treating {len(ports)} port(s) as open for HTTP(S) only")
    else:
        sem = asyncio.Semaphore(concurrency)
        with Progress(
            SpinnerColumn(style="info"),
            TextColumn("[info]{task.description}[/info]"),
            BarColumn(bar_width=36, complete_style="bright_green", finished_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            tcp_task = progress.add_task(f"TCP  {target}", total=len(ports))

            async def tcp_one(p: int) -> PortResult:
                async with sem:
                    await jitter_sleep(delay_lo, delay_hi)
                    open_, err = await tcp_probe(target, p, connect_timeout)
                progress.advance(tcp_task)
                return PortResult(port=p, tcp_open=open_, tcp_error=err)

            tcp_results = await asyncio.gather(*(tcp_one(p) for p in ports))

    open_ports = [r for r in tcp_results if r.tcp_open]
    by_port = {r.port: r for r in tcp_results}
    if not open_ports:
        return tcp_results

    schemes: list[str] = []
    if try_http:
        schemes.append("http")
    if try_https:
        schemes.append("https")

    jobs = [(r.port, scheme, path) for r in open_ports for scheme in schemes for path in paths]
    http_sem = asyncio.Semaphore(max(4, concurrency // 2))
    limits = httpx.Limits(
        max_connections=max(8, concurrency // 2),
        max_keepalive_connections=max(4, concurrency // 4),
    )
    default_ua = user_agents[0] if user_agents else USER_AGENTS[0]
    headers = {"User-Agent": default_ua, "Accept": "*/*"}
    headers.update(custom_headers)
    if host_header:
        headers["Host"] = host_header

    client_kwargs: dict = {
        "follow_redirects": follow_redirects,
        "verify": verify_tls,
        "timeout": httpx.Timeout(http_timeout, connect=connect_timeout),
        "headers": headers,
        "limits": limits,
        "http2": False,
        "auth": auth,
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    with Progress(
        SpinnerColumn(style="http"),
        TextColumn("[http]{task.description}[/http]"),
        BarColumn(bar_width=36, complete_style="bright_cyan", finished_style="cyan"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        http_task = progress.add_task(f"{method}  {target}", total=len(jobs))
        async with httpx.AsyncClient(**client_kwargs) as client:

            async def one(port: int, scheme: str, path: str) -> tuple[int, HttpHit]:
                async with http_sem:
                    await jitter_sleep(delay_lo, delay_hi)
                    extra = None
                    if rotate_agent and user_agents:
                        extra = {"User-Agent": random.choice(user_agents)}
                    hit = await http_probe(
                        client,
                        method,
                        scheme,
                        target,
                        port,
                        path,
                        keep_body,
                        max_body,
                        retries,
                        extra,
                    )
                    if scheme == "https" and collect_certs and (hit.status is not None or "ssl" in hit.error.lower()):
                        hit.tls = await asyncio.to_thread(collect_tls, target, port, connect_timeout)
                        if hit.tls and hit.tls.expired:
                            hit.tags.append("expired-cert")
                progress.advance(http_task)
                return port, hit

            pairs = await asyncio.gather(*(one(port, scheme, path) for port, scheme, path in jobs))

    for port, hit in pairs:
        if status_allow or grep:
            if not hit_passes_filters(hit, status_allow, grep) and hit.status is not None:
                hit.tags.append("filtered")
        by_port[port].hits.append(hit)
        if sink and "filtered" not in hit.tags:
            sink.capture(target, port, hit)

    return [by_port[p] for p in ports]


async def grab_open_banners(host: str, results: list[PortResult], timeout: float, concurrency: int) -> None:
    sem = asyncio.Semaphore(max(4, concurrency // 4))

    async def one(result: PortResult) -> None:
        if not result.tcp_open or any(speaking(h) for h in result.hits):
            return
        async with sem:
            result.banner = await banner_grab(host, result.port, timeout)

    await asyncio.gather(*(one(r) for r in results))


def analyze_hits(report: HostReport) -> None:
    for result in report.results:
        for hit in result.hits:
            if not speaking(hit) or "filtered" in hit.tags:
                continue
            path = urlparse(hit.url).path.lower()
            if hit.status and hit.status < 400 and (path in {"", "/"} or "text/html" in hit.content_type):
                report.findings.extend(score_security_headers(hit.url, hit.headers, hit.scheme))
            elif header_lookup(hit.headers, "set-cookie"):
                report.findings.extend(score_cookie_flags(hit.url, header_lookup(hit.headers, "set-cookie"), hit.scheme))
            if path.endswith("security.txt") and hit.status and hit.status < 400 and hit.body:
                report.findings.extend(parse_security_txt(hit.url, hit.body, hit.status))
                hit.tags.append("security-txt")
            if hit.status in {200, 206} and any(
                token in urlparse(hit.url).path.lower()
                for token in ("/.git", "/.env", "/.svn", "/.htpasswd", "/dump.sql", "/backup.")
            ):
                report.findings.append(
                    Finding("high", "Sensitive path responded", "Artifact-style path returned a body", url=hit.url)
                )
            if hit.body:
                js_urls, _secrets, js_findings = extract_js_intel(hit.final_url or hit.url, hit.body)
                report.js_urls.extend(js_urls)
                report.findings.extend(js_findings)
            path = urlparse(hit.url).path.lower()
            if path.endswith("favicon.ico") and hit.body and hit.status and hit.status < 400:
                digest = str(shodan_favicon_hash(hit.body))
                report.favicon_hash = digest
                report.favicon_hint = FAVICON_HINTS.get(digest, "")
                hit.tags.append(f"favicon:{digest}")
            acao = header_lookup(hit.headers, "access-control-allow-origin")
            if acao and acao not in {"*", "null"} and acao != hit.url:
                if "webhawk" in acao.lower():
                    report.findings.append(
                        Finding("high", "Reflected CORS origin", "Server echoed a foreign Origin", url=hit.url, evidence=acao)
                    )
        if result.banner:
            report.banners.append(f"{result.port}/tcp {result.banner}")
            report.findings.append(Finding("info", f"Banner on port {result.port}", result.banner))
    report.js_urls = dedupe(report.js_urls)
    # de-dupe findings
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in report.findings:
        key = (finding.severity, finding.title, finding.url)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    report.findings = unique


async def cors_probe(report: HostReport, timeout: float, verify_tls: bool, proxy: str | None) -> None:
    origins = ["https://webhawk.invalid", "http://127.0.0.1"]
    live = [
        hit
        for result in report.results
        for hit in result.hits
        if speaking(hit) and urlparse(hit.url).path in {"", "/"}
    ]
    if not live:
        live = [hit for result in report.results for hit in result.hits if speaking(hit)][:4]
    kwargs: dict = {"timeout": timeout, "verify": verify_tls, "follow_redirects": False}
    if proxy:
        kwargs["proxy"] = proxy
    async with httpx.AsyncClient(**kwargs) as client:
        for hit in live[:6]:
            for origin in origins:
                try:
                    resp = await client.request(
                        "OPTIONS",
                        hit.url,
                        headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
                    )
                except Exception:
                    continue
                acao = resp.headers.get("access-control-allow-origin", "")
                if acao == origin or acao == "*":
                    report.findings.append(
                        Finding(
                            "high" if acao == origin else "medium",
                            "Permissive CORS",
                            f"OPTIONS Origin {origin} → {acao}",
                            url=hit.url,
                            evidence=acao,
                        )
                    )


def write_markdown(path: Path, reports: list[HostReport], elapsed: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# WebHawk report",
        "",
        f"Generated `{datetime.now(timezone.utc).isoformat()}` by WebHawk {VERSION}.",
        f"Elapsed **{elapsed:.2f}s** across **{len(reports)}** host(s).",
        "",
        "Authorized assessment notes only. Confirm scope before acting on findings.",
        "",
    ]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for report in reports:
        lines += [f"## {report.target}", ""]
        if report.resolved:
            lines.append("Resolved: " + ", ".join(f"`{ip}`" for ip in report.resolved))
            lines.append("")
        if report.favicon_hash:
            hint = f" ({report.favicon_hint})" if report.favicon_hint else ""
            lines.append(f"Favicon mmh3: `{report.favicon_hash}`{hint}")
            lines.append("")
        if report.dns:
            lines.append("### DNS")
            for rtype, recs in report.dns.items():
                lines.append(f"- **{rtype}**: " + ", ".join(f"`{r}`" for r in recs[:8]))
            lines.append("")
        if report.ct_names:
            lines.append("### Certificate transparency")
            for name in report.ct_names[:40]:
                lines.append(f"- `{name}`")
            lines.append("")
        live = [
            hit
            for result in report.results
            for hit in result.hits
            if speaking(hit) and "filtered" not in hit.tags
        ]
        if live:
            lines.append("### Live HTTP(S)")
            lines.append("| Port | URL | Status | Server | Title | Tags |")
            lines.append("| ---: | --- | --- | --- | --- | --- |")
            for hit in live:
                port = urlparse(hit.url).port or (443 if hit.scheme == "https" else 80)
                title = (hit.title or "").replace("|", "/")
                tags = ", ".join(hit.tags)
                lines.append(
                    f"| {port} | `{hit.url}` | {hit.status} | {hit.server or ''} | {title} | {tags} |"
                )
            lines.append("")
        if report.banners:
            lines.append("### Non-HTTP banners")
            for banner in report.banners:
                lines.append(f"- `{banner}`")
            lines.append("")
        if report.js_urls:
            lines.append("### JavaScript / API URLs")
            for url in report.js_urls[:40]:
                lines.append(f"- `{url}`")
            lines.append("")
        findings = sorted(report.findings, key=lambda f: order.get(f.severity, 9))
        if findings:
            lines.append("### Findings")
            for finding in findings:
                loc = f" — `{finding.url}`" if finding.url else ""
                extra = f" ({finding.evidence})" if finding.evidence else ""
                lines.append(f"- **{finding.severity.upper()}** {finding.title}{loc}. {finding.detail}{extra}")
            lines.append("")
        else:
            lines.append("_No extra findings recorded for this host._")
            lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def render_host(report: HostReport, only_live: bool) -> None:
    open_tcp = [r for r in report.results if r.tcp_open]
    live_hits = [h for r in open_tcp for h in r.hits if speaking(h) and "filtered" not in h.tags]
    summary = Table.grid(padding=(0, 2))
    summary.add_row("[info]target[/info]", f"[bold]{report.target}[/bold]")
    summary.add_row("[info]resolved[/info]", ", ".join(report.resolved) or "[muted]n/a[/muted]")
    summary.add_row("[info]ports tested[/info]", str(len(report.results)))
    summary.add_row("[open]tcp open[/open]", str(len(open_tcp)))
    summary.add_row("[http]live http(s)[/http]", str(len(live_hits)))
    summary.add_row("[muted]elapsed[/muted]", f"{report.elapsed:.2f}s")
    console.print(Panel(summary, title=f"[title]{report.target}[/title]", border_style="magenta"))

    if not open_tcp:
        console.print("[err]No TCP-open ports in the selected set.[/err]\n")
        return

    table = Table(
        box=box.ROUNDED,
        border_style="bright_blue",
        header_style="bold white",
        expand=True,
        show_lines=False,
    )
    table.add_column("port", style="port", justify="right", no_wrap=True)
    table.add_column("proto", no_wrap=True)
    table.add_column("status", no_wrap=True)
    table.add_column("server")
    table.add_column("title / error")
    table.add_column("tags")
    table.add_column("ms", justify="right", no_wrap=True)

    rows = 0
    for r in open_tcp:
        spoken = [h for h in r.hits if speaking(h)]
        if only_live and not spoken:
            continue
        if spoken:
            for hit in spoken:
                status = (
                    Text(f"{hit.status} {hit.reason}".strip(), style=status_style(hit.status))
                    if hit.status is not None
                    else Text(hit.error or "no response", style="err")
                )
                detail = hit.title or hit.location or hit.error or hit.snippet
                tags = " ".join(hit.tags[:5])
                table.add_row(
                    str(r.port),
                    Text(hit.scheme.upper(), style=hit.scheme),
                    status,
                    hit.server or hit.powered_by or Text("—", style="muted"),
                    (detail[:72] + "…") if len(detail) > 72 else detail or Text("—", style="muted"),
                    Text(tags, style="tag") if tags else Text("—", style="muted"),
                    f"{hit.elapsed_ms:.0f}",
                )
                rows += 1
        else:
            why = "; ".join(sorted({h.error for h in r.hits if h.error})) or "no http/https response"
            table.add_row(
                str(r.port),
                Text("TCP", style="muted"),
                Text("open, no HTTP", style="warn"),
                Text("—", style="muted"),
                why[:72],
                Text("—", style="muted"),
                "—",
            )
            rows += 1

    if rows:
        console.print(table)

    for r in open_tcp:
        for hit in r.hits:
            if not speaking(hit) or "filtered" in hit.tags:
                continue
            body = Table.grid(padding=(0, 1))
            body.add_row("[info]url[/info]", f"[{hit.scheme}]{hit.url}[/{hit.scheme}]")
            if hit.final_url != hit.url:
                body.add_row("[info]final[/info]", hit.final_url)
            if hit.status is not None:
                body.add_row("[info]status[/info]", Text(f"{hit.status} {hit.reason}".strip(), style=status_style(hit.status)))
            if hit.server:
                body.add_row("[info]server[/info]", hit.server)
            if hit.powered_by:
                body.add_row("[info]powered-by[/info]", hit.powered_by)
            if hit.content_type:
                body.add_row("[info]type[/info]", hit.content_type)
            if hit.location:
                body.add_row("[info]location[/info]", hit.location)
            if hit.title:
                body.add_row("[info]title[/info]", f"[title]{hit.title}[/title]")
            if hit.tags:
                body.add_row("[info]tags[/info]", Text(", ".join(hit.tags), style="tag"))
            if hit.sha256:
                body.add_row("[muted]hash[/muted]", hit.sha256)
            body.add_row("[muted]bytes[/muted]", str(hit.bytes_read))
            if hit.tls and not hit.tls.error:
                cert_line = f"{hit.tls.version}  {hit.tls.subject or '—'}  exp {hit.tls.not_after or '—'}"
                if hit.tls.expired:
                    cert_line += "  [err]EXPIRED[/err]"
                body.add_row("[cert]tls[/cert]", cert_line)
                if hit.tls.issuer:
                    body.add_row("[cert]issuer[/cert]", hit.tls.issuer)
            if hit.snippet:
                body.add_row("[muted]body[/muted]", Text(hit.snippet, style="muted"))
            border = "green" if hit.status and 200 <= hit.status < 300 else "cyan"
            console.print(
                Panel(
                    body,
                    title=f"[port]:{r.port}[/port] [{hit.scheme}]{hit.scheme.upper()}[/{hit.scheme}]",
                    border_style=border,
                )
            )
    if report.findings:
        table = Table(box=box.SIMPLE, header_style="bold white", border_style="yellow", expand=True)
        table.add_column("sev", no_wrap=True)
        table.add_column("finding")
        table.add_column("where")
        style_map = {"critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "muted"}
        for finding in report.findings[:30]:
            table.add_row(
                Text(finding.severity.upper(), style=style_map.get(finding.severity, "muted")),
                finding.title,
                finding.url or Text("—", style="muted"),
            )
        console.print(table)
    if report.dns:
        bits = [f"{k}:{len(v)}" for k, v in report.dns.items()]
        console.print("[info]dns[/info] " + "  ".join(bits))
    if report.ct_names:
        console.print(f"[cert]ct names[/cert] {len(report.ct_names)}")
    if report.favicon_hash:
        hint = f"  [tag]{report.favicon_hint}[/tag]" if report.favicon_hint else ""
        console.print(f"[info]favicon mmh3[/info] {report.favicon_hash}{hint}")
    console.print()


def reports_to_json(reports: list[HostReport], elapsed: float) -> dict:
    def tls_dict(t: TlsInfo | None) -> dict | None:
        return asdict(t) if t else None

    def hit_dict(h: HttpHit) -> dict:
        data = asdict(h)
        data.pop("body", None)
        data["tls"] = tls_dict(h.tls)
        return data

    return {
        "tool": "WebHawk",
        "version": VERSION,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 3),
        "hosts": [
            {
                "target": r.target,
                "resolved": r.resolved,
                "elapsed_seconds": round(r.elapsed, 3),
                "dns": r.dns,
                "ct_names": r.ct_names,
                "favicon_hash": r.favicon_hash,
                "favicon_hint": r.favicon_hint,
                "js_urls": r.js_urls,
                "banners": r.banners,
                "findings": [asdict(f) for f in r.findings],
                "ports": [
                    {
                        "port": p.port,
                        "tcp_open": p.tcp_open,
                        "tcp_error": p.tcp_error,
                        "hits": [hit_dict(h) for h in p.hits],
                    }
                    for p in r.results
                    if p.tcp_open
                ],
            }
            for r in reports
        ],
    }


def write_csv(path: Path, reports: list[HostReport]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "target",
                "port",
                "scheme",
                "url",
                "final_url",
                "status",
                "server",
                "title",
                "tags",
                "sha256",
                "bytes",
                "ms",
            ]
        )
        for report in reports:
            for result in report.results:
                for hit in result.hits:
                    if not speaking(hit):
                        continue
                    writer.writerow(
                        [
                            report.target,
                            result.port,
                            hit.scheme,
                            hit.url,
                            hit.final_url,
                            hit.status,
                            hit.server,
                            hit.title,
                            ",".join(hit.tags),
                            hit.sha256,
                            hit.bytes_read,
                            f"{hit.elapsed_ms:.1f}",
                        ]
                    )


def build_parser(prog: str = "webhawk") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="WebHawk scan — map HTTP/HTTPS attack surface on authorized hosts.",
        epilog="Examples:\n"
        "  webhawk 127.0.0.1\n"
        "  webhawk scan -l targets.txt --output-dir ./hawk-out\n"
        "  webhawk 127.0.0.1 --user-agent agents.txt --paths paths.txt -H headers.txt\n"
        "\n"
        "With no subcommand, arguments are a scan.\n"
        "Other commands: webhawk modules, webhawk doctor, webhawk examples.\n"
        "A host named like a command: webhawk scan modules\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="IPs, hostnames, URLs, or CIDR ranges")
    p.add_argument("-l", "--targets-file", metavar="FILE", help="File of targets, one per line (# comments ok)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--common", action="store_true", help="Common web ports (default)")
    g.add_argument("--ports", metavar="SPEC", help="Ports/ranges, e.g. 80,443,8000-8010")
    g.add_argument("--range", dest="port_range", metavar="START-END", help="Inclusive port range")
    g.add_argument("--all", action="store_true", help="Every TCP port 1-65535 (requires --authorized)")
    p.add_argument("--ports-file", metavar="FILE", help="File of ports / ranges, one spec per line")
    p.add_argument("--exclude-ports", metavar="SPEC", help="Ports to skip, same syntax as --ports")
    p.add_argument(
        "--authorized",
        "--i-own-this",
        dest="authorized",
        action="store_true",
        help="Acknowledge authorization for large sweeps / CIDRs (--i-own-this still works)",
    )
    p.add_argument("--paths", default="/", help="Comma-separated paths, or a file of paths")
    p.add_argument("--paths-file", metavar="FILE", help="File of paths, one per line")
    p.add_argument("--concurrency", type=int, default=256, help="Max parallel TCP connects (default: 256)")
    p.add_argument("--connect-timeout", type=float, default=1.2, help="TCP connect timeout seconds")
    p.add_argument("--http-timeout", type=float, default=4.0, help="HTTP request timeout seconds")
    p.add_argument("--delay", default="0", help="Delay seconds, or a jitter range like 0.5-2.0")
    p.add_argument("--discover", action="store_true", help="Add common artifact paths (.git, .env, robots.txt, …)")
    p.add_argument("--mutate-paths", action="store_true", help="Also request path.bak / .old / .zip / ~ and friends")
    p.add_argument("--mutate-ext", help="Extra mutation suffixes, comma-separated (e.g. .inc,.dist)")
    p.add_argument("--params", action="store_true", help="Probe common parameters on endpoint-like paths")
    p.add_argument("--params-file", metavar="FILE", help="Extra parameter names, one per line")
    p.add_argument("--score-headers", action="store_true", help="Score missing security headers on live responses")
    p.add_argument("--cors", action="store_true", help="Send a CORS preflight to live URLs")
    p.add_argument("--extract-js", action="store_true", help="Parse HTML/JS for URLs and key-like assignments")
    p.add_argument("--favicon", action="store_true", help="Fetch /favicon.ico and print a Shodan-style mmh3 hash")
    p.add_argument("--dns", action="store_true", help="Enumerate A/AAAA/MX/NS/TXT/DMARC via DNS-over-HTTPS")
    p.add_argument("--ct", action="store_true", help="Query crt.sh for certificate-transparency names")
    p.add_argument("--banners", action="store_true", help="Read banners from TCP-open ports that are not HTTP")
    p.add_argument("--md", metavar="FILE", help="Write a markdown findings report")
    p.add_argument("--screenshots", metavar="DIR", help="Capture Playwright screenshots of live pages (optional extra)")
    p.add_argument("--intel", action="store_true", help="Enable discover + header score + js + favicon + dns")
    p.add_argument("--retries", type=int, default=0, help="Retries per HTTP request on timeout/connect errors")
    p.add_argument("--http-only", action="store_true", help="Skip HTTPS")
    p.add_argument("--https-only", action="store_true", help="Skip HTTP")
    p.add_argument("--follow-redirects", action="store_true", help="Follow HTTP redirects")
    p.add_argument("--insecure", action="store_true", help="Do not verify TLS certificates")
    p.add_argument("--no-cert", action="store_true", help="Do not fetch TLS certificate metadata")
    p.add_argument("--skip-tcp", action="store_true", help="Skip the TCP connect scan; send HTTP(S) to every selected port")
    p.add_argument(
        "--method",
        default="GET",
        choices=sorted(HTTP_METHODS),
        help="HTTP method (default: GET). HEAD is lighter; OPTIONS shows Allow",
    )
    p.add_argument("--host-header", help="Override Host header (vhost on an IP)")
    p.add_argument("-H", "--header", action="append", default=[], metavar="HEADER", help="Custom header 'Name: value' (repeatable) or a headers file")
    p.add_argument("--headers-file", metavar="FILE", help="File of custom headers, one 'Name: value' per line")
    p.add_argument("--auth", metavar="USER:PASS", help="HTTP Basic authentication")
    p.add_argument("--user-agent", default=USER_AGENTS[0], help="User-Agent string, or a file of User-Agents")
    p.add_argument("--user-agents-file", metavar="FILE", help="File of User-Agents, one per line")
    p.add_argument("--random-agent", action="store_true", help="Pick a random User-Agent from the pool for the whole scan")
    p.add_argument("--rotate-agent", action="store_true", help="Pick a random User-Agent from the pool on every request")
    p.add_argument("--proxy", help="HTTP proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--status", help="Only treat these codes as live, e.g. 200,301-302,401")
    p.add_argument("--grep", help="Regex that title/body/server must match to count as live")
    p.add_argument("--only-live", action="store_true", help="Hide TCP-open ports that do not speak HTTP(S)")
    p.add_argument("--save-urls", metavar="FILE", help="Append live URLs (one per line) to FILE")
    p.add_argument("--save-source", metavar="DIR", help="Write response bodies of live URLs into DIR")
    p.add_argument("--save-headers", metavar="DIR", help="Write interesting response headers into DIR")
    p.add_argument("--output-dir", metavar="DIR", help="Shortcut: write live.txt, pages/, headers/, JSON and CSV into DIR")
    p.add_argument("--max-body", type=int, default=262144, help="Max bytes saved per body (default: 256KiB)")
    p.add_argument("--json", metavar="FILE", help="Write a JSON report")
    p.add_argument("--csv", metavar="FILE", help="Write a CSV report of live URLs")
    p.add_argument("--quiet", action="store_true", help="Skip the banner")
    p.add_argument("--version", action="version", version=f"WebHawk {VERSION}")
    return p


def collect_targets(args: argparse.Namespace) -> list[str]:
    raw: list[str] = list(args.targets)
    if args.targets_file:
        raw.extend(load_target_file(Path(args.targets_file)))
    if not raw:
        raise SystemExit("No targets given. Pass hosts or --targets-file.")

    expanded: list[str] = []
    seen: set[str] = set()
    for token in raw:
        cidr = expand_cidr(token) if "/" in token and "://" not in token else None
        pieces = cidr if cidr is not None else [normalize_host(token)]
        if cidr is not None:
            if len(cidr) > MAX_CIDR_HOSTS_HARD:
                raise SystemExit(f"CIDR {token} expands to {len(cidr)} hosts (hard cap {MAX_CIDR_HOSTS_HARD}).")
            if len(cidr) > MAX_CIDR_HOSTS_SOFT and not args.authorized:
                raise SystemExit(
                    f"CIDR {token} expands to {len(cidr)} hosts. Re-run with --authorized only if you own the range."
                )
        for host in pieces:
            host = host.strip()
            if host and host not in seen:
                seen.add(host)
                expanded.append(host)
    return expanded


def choose_ports(args: argparse.Namespace) -> list[int]:
    ports: list[int] = []
    if args.all:
        ports = list(range(1, 65536))
    elif args.ports:
        ports = parse_ports(args.ports)
    elif args.port_range:
        ports = parse_ports(args.port_range)
    else:
        ports = list(COMMON_WEB_PORTS)
    if args.ports_file:
        extra: list[int] = []
        for line in load_list_file(Path(args.ports_file).expanduser()):
            extra.extend(parse_ports(line.replace(" ", "")))
        if args.all or args.ports or args.port_range:
            ports = sorted(set(ports) | set(extra))
        else:
            # A ports file should replace the default common list when it is
            # the only port source besides excludes.
            ports = sorted(set(extra)) or ports
    if args.exclude_ports:
        skip = set(parse_ports(args.exclude_ports))
        ports = [p for p in ports if p not in skip]
    return ports


def apply_output_dir(args: argparse.Namespace) -> None:
    if not args.output_dir:
        return
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if not args.save_urls:
        args.save_urls = str(out / "live.txt")
    if not args.save_source:
        args.save_source = str(out / "pages")
    if not args.save_headers:
        args.save_headers = str(out / "headers")
    if not args.json:
        args.json = str(out / "webhawk.json")
    if not args.csv:
        args.csv = str(out / "webhawk.csv")
    if not getattr(args, "md", None):
        args.md = str(out / "webhawk.md")


def parse_basic_auth(value: str | None) -> httpx.BasicAuth | None:
    if not value:
        return None
    if ":" not in value:
        raise SystemExit("--auth must be USER:PASS")
    user, password = value.split(":", 1)
    return httpx.BasicAuth(user, password)


def capture_screenshots(report: HostReport, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        console.print("[warn]screenshots skipped[/warn] — install extra package: pip install playwright && playwright install chromium")
        return
    urls = [
        hit.final_url or hit.url
        for result in report.results
        for hit in result.hits
        if speaking(hit) and hit.status and hit.status < 400
    ][:20]
    if not urls:
        return
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 720})
            for url in urls:
                safe = re.sub(r"[^A-Za-z0-9._-]+", "_", url)[:80]
                dest = directory / f"{safe}.png"
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=8000)
                    page.screenshot(path=str(dest), full_page=False)
                except Exception as exc:
                    console.print(f"[muted]screenshot miss {url}: {exc}[/muted]")
            browser.close()
        console.print(f"[ok]screenshots[/ok] {directory}")
    except Exception as exc:
        console.print(f"[warn]screenshots failed:[/warn] {exc}")


def describe_ip(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    flags = []
    if parsed.is_loopback:
        flags.append("loopback")
    if parsed.is_private:
        flags.append("private")
    if parsed.is_link_local:
        flags.append("link-local")
    if parsed.is_multicast:
        flags.append("multicast")
    if parsed.is_global:
        flags.append("public")
    label = ",".join(flags) or "other"
    style = "ok" if parsed.is_private or parsed.is_loopback else "warn"
    return f"[{style}]{ip}[/{style}] [muted]({label})[/muted]"


def scan_main(argv: list[str] | None = None, prog: str = "webhawk") -> int:
    args = build_parser(prog).parse_args(argv)
    blocked = refuse_file_targets(list(args.targets))
    if blocked:
        return blocked
    if not args.quiet:
        banner()

    try:
        apply_output_dir(args)
        targets = collect_targets(args)
        ports = choose_ports(args)
        paths = collect_paths(args.paths, args.paths_file)
        delay_lo, delay_hi = parse_delay_range(args.delay)
        agents = collect_user_agents(args.user_agent, args.user_agents_file, args.random_agent or args.rotate_agent)
        custom_headers = collect_custom_headers(args.header, args.headers_file)
        auth = parse_basic_auth(args.auth)
        extra_params = load_list_file(Path(args.params_file).expanduser()) if args.params_file else []
    except (ValueError, argparse.ArgumentTypeError, FileNotFoundError, OSError) as exc:
        console.print(f"[err]{exc}[/err]")
        return 2
    except SystemExit as exc:
        if exc.args:
            console.print(f"[err]{exc.args[0]}[/err]")
        return 2

    if args.all and not args.authorized:
        console.print("[err]--all scans 65535 ports.[/err] Re-run with [warn]--authorized[/warn] only on hosts you own.")
        return 2
    if len(ports) > 4096 and not args.authorized:
        console.print(f"[err]Refusing to scan {len(ports)} ports without [warn]--authorized[/warn].[/err]")
        return 2
    if args.skip_tcp and len(ports) > 1024 and not args.authorized:
        console.print(
            f"[err]--skip-tcp on {len(ports)} ports sends an HTTP(S) request to each one.[/err] "
            "Add [warn]--authorized[/warn] if that is really the plan."
        )
        return 2

    try_http = not args.https_only
    try_https = not args.http_only
    if not try_http and not try_https:
        console.print("[err]Nothing to do: both --http-only and --https-only set.[/err]")
        return 2

    if args.intel:
        args.discover = True
        args.score_headers = True
        args.extract_js = True
        args.favicon = True
        args.dns = True

    if args.discover:
        paths = dedupe(paths + ARTIFACT_PATHS)
    if args.favicon and "/favicon.ico" not in paths:
        paths = dedupe(paths + ["/favicon.ico"])
    if args.mutate_paths:
        extra_ext = [p.strip() for p in (args.mutate_ext or "").split(",") if p.strip()]
        paths = mutate_paths(paths, extra_ext)
    param_names = list(COMMON_PARAMS)
    if extra_params:
        param_names.extend(extra_params)
    param_names = dedupe(param_names)
    if args.params:
        extras: list[str] = []
        for path in paths:
            if looks_like_endpoint(path) or path == "/":
                for name in param_names[:12]:
                    extras.append(with_query(path, name, "1"))
        paths = dedupe(paths + extras)

    if len(paths) > 400 and not args.authorized:
        console.print(
            f"[err]Refusing {len(paths)} request paths without [warn]--authorized[/warn] "
            "(discover/mutate/params explode quickly).[/err]"
        )
        return 2

    status_allow = parse_status_set(args.status)
    grep = re.compile(args.grep, re.I) if args.grep else None
    if args.random_agent and not args.rotate_agent:
        chosen = random.choice(agents)
        agents = [chosen]
    keep_body = bool(
        args.save_source
        or args.extract_js
        or args.favicon
        or args.score_headers
        or args.intel
        or args.md
        or args.screenshots
    )

    sink = ArtifactSink(
        urls_path=Path(args.save_urls) if args.save_urls else None,
        source_dir=Path(args.save_source) if args.save_source else None,
        header_dir=Path(args.save_headers) if args.save_headers else None,
    )

    console.print(
        f"[info]targets[/info] {len(targets)} · [info]ports[/info] {len(ports)} · "
        f"[info]paths[/info] {len(paths)} · [info]concurrency[/info] {args.concurrency}"
    )
    proto = []
    if try_http:
        proto.append("[http]HTTP[/http]")
    if try_https:
        proto.append("[https]HTTPS[/https]")
    console.print("[info]schemes[/info] " + " + ".join(proto) + f"  [info]method[/info] {args.method}")
    if delay_hi:
        console.print(f"[info]jitter[/info] {delay_lo:.2f}–{delay_hi:.2f}s")
    if args.skip_tcp:
        console.print("[warn]tcp scan[/warn] skipped — HTTP(S) will be sent to every selected port")
    if custom_headers:
        names = ", ".join(custom_headers)
        console.print(f"[info]headers[/info] {len(custom_headers)} custom ({names})")
    if args.rotate_agent:
        console.print(f"[info]user-agent[/info] rotating across {len(agents)} value(s)")
    else:
        shown = agents[0]
        extra = f" (+{len(agents) - 1} more in pool)" if len(agents) > 1 else ""
        console.print(f"[info]user-agent[/info] {shown}{extra}")
    if args.save_urls:
        console.print(f"[info]live urls[/info] {args.save_urls}")
    if args.save_source:
        console.print(f"[info]sources[/info] {args.save_source}")
    console.print()

    reports: list[HostReport] = []
    t_all = time.perf_counter()
    try:
        for target in targets:
            console.print(f"[brand]▸[/brand] [bold]{target}[/bold]")
            try:
                ip_list = resolve_host(target)
            except socket.gaierror as exc:
                console.print(f"[err]DNS failed:[/err] {exc}\n")
                reports.append(HostReport(target, [], [], 0.0))
                continue
            for ip in ip_list:
                console.print("  " + describe_ip(ip))

            t0 = time.perf_counter()
            try:
                results = asyncio.run(
                    scan_host(
                        target=target,
                        ports=ports,
                        connect_timeout=args.connect_timeout,
                        http_timeout=args.http_timeout,
                        concurrency=max(1, args.concurrency),
                        paths=paths,
                        follow_redirects=args.follow_redirects,
                        try_http=try_http,
                        try_https=try_https,
                        verify_tls=not args.insecure,
                        user_agents=agents,
                        rotate_agent=args.rotate_agent,
                        host_header=args.host_header,
                        custom_headers=custom_headers,
                        collect_certs=try_https and not args.no_cert,
                        keep_body=keep_body,
                        max_body=max(1024, args.max_body),
                        delay_lo=delay_lo,
                        delay_hi=delay_hi,
                        proxy=args.proxy,
                        sink=sink,
                        status_allow=status_allow,
                        grep=grep,
                        skip_tcp=args.skip_tcp,
                        method=args.method.upper(),
                        retries=max(0, args.retries),
                        auth=auth,
                    )
                )
            except KeyboardInterrupt:
                raise
            elapsed = time.perf_counter() - t0
            report = HostReport(target, ip_list, results, elapsed)
            if args.dns:
                report.dns = enumerate_dns(target)
            if args.ct:
                report.ct_names = fetch_ct_names(target)
            if args.banners:
                asyncio.run(grab_open_banners(target, results, args.connect_timeout, max(1, args.concurrency)))
            if args.score_headers or args.extract_js or args.favicon or args.md or args.intel or args.discover:
                analyze_hits(report)
            if args.cors:
                asyncio.run(cors_probe(report, args.http_timeout, not args.insecure, args.proxy))
            if args.screenshots:
                capture_screenshots(report, Path(args.screenshots))
            reports.append(report)
            console.print()
            render_host(report, only_live=args.only_live)
    except KeyboardInterrupt:
        console.print("\n[warn]Interrupted.[/warn]")
        sink.close()
        return 130
    finally:
        sink.close()

    total = time.perf_counter() - t_all
    live_count = sum(
        1
        for r in reports
        for p in r.results
        for h in p.hits
        if speaking(h) and "filtered" not in h.tags
    )
    console.print(
        Panel.fit(
            f"[ok]{len(reports)}[/ok] host(s)  ·  [http]{live_count}[/http] live URL(s)  ·  [muted]{total:.2f}s[/muted]",
            title="[brand]webhawk done[/brand]",
            border_style="magenta",
        )
    )

    if args.json:
        Path(args.json).write_text(json.dumps(reports_to_json(reports, total), indent=2), encoding="utf-8")
        console.print(f"[ok]wrote[/ok] {args.json}")
    if args.csv:
        write_csv(Path(args.csv), reports)
        console.print(f"[ok]wrote[/ok] {args.csv}")
    if args.md:
        write_markdown(Path(args.md), reports, total)
        console.print(f"[ok]wrote[/ok] {args.md}")
    if args.save_urls:
        console.print(f"[ok]live urls[/ok] {args.save_urls}  ({len(sink.seen_urls)} unique)")
    if args.save_source:
        console.print(f"[ok]sources[/ok] {args.save_source}")

    return 0


def main(argv: list[str] | None = None) -> int:
    """Toolkit entry. Targets and scan flags still run scan_main."""
    from hawk.cli import dispatch

    return dispatch(
        argv,
        scan_main=scan_main,
        build_parser=build_parser,
        tool_file=Path(__file__).resolve(),
    )


if __name__ == "__main__":
    sys.exit(main())
