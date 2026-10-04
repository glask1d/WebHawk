#!/usr/bin/env python3
"""
Pulse
-----
Read URLs from a text file (or stdin) and report which ones are live.

Features
  • Concurrent checks with a live progress bar
  • Colorful grouping by status family (2xx / 3xx / 4xx / 5xx / errors)
  • Optional redirect following + full redirect-chain display
  • Response times, final URL, content-type
  • Auto-prefix https:// when a scheme is missing
  • JSON / CSV export
  • Custom timeout, concurrency, user-agent, retries
  • Skip comments (#) and blank lines
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

console = Console()

DEFAULT_UA = "Mozilla/5.0 (compatible; Pulse/1.0; +https://github.com/pulse)"

# Status-family colors used throughout the UI
FAMILY_STYLE = {
    "2xx": "bold green",
    "3xx": "bold cyan",
    "4xx": "bold yellow",
    "5xx": "bold red",
    "error": "bold magenta",
}

FAMILY_LABEL = {
    "2xx": "LIVE  ·  2xx Success",
    "3xx": "REDIRECT  ·  3xx",
    "4xx": "CLIENT ERROR  ·  4xx",
    "5xx": "SERVER ERROR  ·  5xx",
    "error": "UNREACHABLE  ·  Network / TLS / DNS",
}


@dataclass
class CheckResult:
    url: str
    ok: bool
    status: int | None = None
    reason: str = ""
    family: str = "error"
    elapsed_ms: int = 0
    final_url: str = ""
    content_type: str = ""
    error: str = ""
    redirects: list[str] = field(default_factory=list)

    def to_row(self) -> dict:
        data = asdict(self)
        data["redirects"] = " -> ".join(self.redirects) if self.redirects else ""
        return data


def status_family(code: int | None) -> str:
    if code is None:
        return "error"
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if 500 <= code < 600:
        return "5xx"
    return "error"


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    parsed = urlparse(raw)
    if not parsed.scheme:
        return f"https://{raw}"
    return raw


def load_urls(path: Path | None) -> list[str]:
    """Load unique URLs from a file or stdin. Skip blanks and # comments."""
    if path is None or str(path) == "-":
        lines = sys.stdin.read().splitlines()
        source = "stdin"
    else:
        if not path.exists():
            console.print(f"[bold red]File not found:[/] {path}")
            sys.exit(1)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        source = str(path)

    seen: set[str] = set()
    urls: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        url = normalize_url(stripped)
        if url not in seen:
            seen.add(url)
            urls.append(url)

    if not urls:
        console.print(f"[bold red]No URLs found in[/] {source}")
        sys.exit(1)
    return urls


async def check_one(
    client: httpx.AsyncClient,
    url: str,
    follow: bool,
    retries: int,
) -> CheckResult:
    last_error = ""
    attempts = max(1, retries + 1)

    for attempt in range(attempts):
        start = time.perf_counter()
        try:
            response = await client.get(url, follow_redirects=follow)
            elapsed = int((time.perf_counter() - start) * 1000)

            chain = [str(r.url) for r in response.history]
            if chain and str(response.url) not in chain:
                chain.append(str(response.url))

            family = status_family(response.status_code)
            # "Live" in the everyday sense: we got a 2xx, or a 3xx that we
            # were told *not* to follow (the endpoint itself answered).
            ok = family == "2xx" or (family == "3xx" and not follow)

            ctype = response.headers.get("content-type", "")
            if ";" in ctype:
                ctype = ctype.split(";", 1)[0].strip()

            return CheckResult(
                url=url,
                ok=ok,
                status=response.status_code,
                reason=response.reason_phrase or "",
                family=family,
                elapsed_ms=elapsed,
                final_url=str(response.url),
                content_type=ctype,
                redirects=chain if len(chain) > 1 else [],
            )
        except httpx.TimeoutException:
            last_error = "timeout"
        except httpx.ConnectError as exc:
            msg = str(exc) or type(exc).__name__
            if "CERTIFICATE" in msg.upper() or "SSL" in msg.upper():
                last_error = f"tls error: {msg}"
            else:
                last_error = f"connection failed: {msg}"
        except httpx.TooManyRedirects:
            last_error = "too many redirects"
        except httpx.UnsupportedProtocol:
            last_error = "unsupported protocol"
        except httpx.HTTPError as exc:
            last_error = str(exc) or type(exc).__name__
        except Exception as exc:  # noqa: BLE001 — surface unexpected errors
            last_error = f"{type(exc).__name__}: {exc}"

        if attempt < attempts - 1:
            await asyncio.sleep(0.4 * (attempt + 1))

    return CheckResult(
        url=url,
        ok=False,
        family="error",
        error=last_error,
    )


async def run_checks(
    urls: list[str],
    *,
    follow: bool,
    timeout: float,
    concurrency: int,
    retries: int,
    user_agent: str,
    insecure: bool,
    method_note: str,
) -> list[CheckResult]:
    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=concurrency,
    )
    headers = {"User-Agent": user_agent, "Accept": "*/*"}

    results: list[CheckResult] = []
    sem = asyncio.Semaphore(concurrency)

    # HTTP/2 is nice-to-have; fall back cleanly if the extra is missing.
    try:
        import h2  # noqa: F401
        use_http2 = True
    except ImportError:
        use_http2 = False

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=min(10.0, timeout)),
        headers=headers,
        limits=limits,
        verify=not insecure,
        http2=use_http2,
    ) as client:

        async def bound(url: str) -> CheckResult:
            async with sem:
                return await check_one(client, url, follow, retries)

        tasks = [asyncio.create_task(bound(u)) for u in urls]

        progress = Progress(
            SpinnerColumn(style="bold cyan"),
            TextColumn("[bold]Taking pulse[/]"),
            BarColumn(bar_width=36, complete_style="green", finished_style="bold green"),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )

        console.print()
        console.print(
            Panel(
                f"[bold]{len(urls)}[/] URL(s)  ·  "
                f"concurrency [bold]{concurrency}[/]  ·  "
                f"timeout [bold]{timeout:g}s[/]  ·  "
                f"retries [bold]{retries}[/]  ·  "
                f"{method_note}",
                title="[bold cyan]Pulse[/]",
                border_style="cyan",
                padding=(0, 2),
            )
        )

        with progress:
            task_id = progress.add_task("check", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                result = await coro
                results.append(result)
                progress.advance(task_id)

    # Preserve input order
    order = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda r: order.get(r.url, 0))
    return results


def style_status(status: int | None, family: str) -> Text:
    if status is None:
        return Text("----", style=FAMILY_STYLE[family])
    return Text(str(status), style=FAMILY_STYLE[family])


def render_results(
    results: list[CheckResult],
    *,
    follow: bool,
    show_redirects: bool,
    only: str | None,
) -> None:
    grouped: dict[str, list[CheckResult]] = defaultdict(list)
    family_order = ["2xx", "3xx", "4xx", "5xx", "error"]
    for r in results:
        grouped[r.family].append(r)

    if only:
        keep = {s.strip() for s in only.split(",") if s.strip()}
        family_order = [f for f in family_order if f in keep]
        extra_status = {k for k in keep if k.isdigit()}
    else:
        extra_status = set()

    shown = 0
    for family in family_order:
        rows = grouped.get(family, [])
        if extra_status:
            rows = [r for r in rows if r.status is not None and str(r.status) in extra_status]
        if not rows:
            continue

        style = FAMILY_STYLE[family]
        table = Table(
            title=f"[{style}]{FAMILY_LABEL[family]}[/{style}]  ({len(rows)})",
            box=box.ROUNDED,
            header_style="bold",
            border_style=style.split()[-1],
            show_lines=False,
            pad_edge=False,
            expand=True,
        )
        table.add_column("Code", justify="right", width=6)
        table.add_column("ms", justify="right", width=7)
        table.add_column("URL", overflow="fold", ratio=3)
        table.add_column("Final / Info", overflow="fold", ratio=3)
        table.add_column("Type", overflow="fold", max_width=24)

        for r in rows:
            info = r.error or r.reason
            final = r.final_url if r.final_url and r.final_url != r.url else ""
            info_cell = final or info
            if show_redirects and r.redirects:
                chain = " → ".join(r.redirects)
                info_cell = chain if not info_cell else f"{info_cell}\n{chain}"

            table.add_row(
                style_status(r.status, r.family),
                Text(str(r.elapsed_ms) if r.elapsed_ms else "—", style="dim"),
                Text(r.url, style="white"),
                Text(info_cell, style="dim cyan" if final else "dim"),
                Text(r.content_type or "", style="dim"),
            )
            shown += 1

        console.print()
        console.print(table)

    if shown == 0:
        console.print("\n[yellow]No results matched the current filter.[/]")


def render_summary(results: list[CheckResult], elapsed_s: float) -> None:
    counts = defaultdict(int)
    for r in results:
        counts[r.family] += 1

    live = sum(1 for r in results if r.ok)
    dead = len(results) - live
    times = [r.elapsed_ms for r in results if r.elapsed_ms]
    avg = int(sum(times) / len(times)) if times else 0

    bits = Text.assemble(
        ("  ", ""),
        (f"{live} live", "bold green"),
        ("   ", ""),
        (f"{dead} down", "bold red"),
        ("   ", ""),
        (f"{len(results)} total", "bold"),
        ("\n  ", ""),
        (f"2xx {counts['2xx']}", "green"),
        ("  ·  ", "dim"),
        (f"3xx {counts['3xx']}", "cyan"),
        ("  ·  ", "dim"),
        (f"4xx {counts['4xx']}", "yellow"),
        ("  ·  ", "dim"),
        (f"5xx {counts['5xx']}", "red"),
        ("  ·  ", "dim"),
        (f"err {counts['error']}", "magenta"),
        ("\n  ", ""),
        (f"avg {avg} ms", "dim"),
        ("  ·  ", "dim"),
        (f"wall {elapsed_s:.2f}s", "dim"),
    )

    console.print()
    console.print(
        Panel(bits, title="[bold]Summary[/]", border_style="white", padding=(0, 1))
    )


def export_json(results: list[CheckResult], path: Path) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(results),
        "results": [r.to_row() for r in results],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(f"[green]Wrote JSON[/] → {path}")


def export_csv(results: list[CheckResult], path: Path) -> None:
    fieldnames = [
        "url",
        "ok",
        "status",
        "reason",
        "family",
        "elapsed_ms",
        "final_url",
        "content_type",
        "error",
        "redirects",
    ]
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_row())
    console.print(f"[green]Wrote CSV[/] → {path}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pulse",
        description="Pulse — check a list of URLs and group the results by HTTP status.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python pulse.py urls.txt
  python pulse.py urls.txt --follow-redirects --show-redirects
  python pulse.py urls.txt -c 30 --timeout 8 --json results.json
  python pulse.py urls.txt --only 2xx,error
  cat urls.txt | python pulse.py -
        """,
    )
    p.add_argument(
        "file",
        help="Text file with one URL per line, or '-' for stdin",
    )
    p.add_argument(
        "-f",
        "--follow-redirects",
        action="store_true",
        help="Follow 3xx responses and report the final status instead",
    )
    p.add_argument(
        "--show-redirects",
        action="store_true",
        help="Print the full redirect chain when one exists",
    )
    p.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=20,
        metavar="N",
        help="Max parallel requests (default: 20)",
    )
    p.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        metavar="SEC",
        help="Per-request timeout in seconds (default: 10)",
    )
    p.add_argument(
        "-r",
        "--retries",
        type=int,
        default=1,
        metavar="N",
        help="Retries on network failure (default: 1)",
    )
    p.add_argument(
        "-A",
        "--user-agent",
        default=DEFAULT_UA,
        help="Custom User-Agent header",
    )
    p.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification",
    )
    p.add_argument(
        "--only",
        metavar="FAMILIES",
        help="Only display these families or codes, comma-separated "
        "(e.g. 2xx,3xx or 404,500,error)",
    )
    p.add_argument(
        "--json",
        dest="json_out",
        metavar="PATH",
        help="Write full results to a JSON file",
    )
    p.add_argument(
        "--csv",
        dest="csv_out",
        metavar="PATH",
        help="Write full results to a CSV file",
    )
    return p


def validate_args(args: argparse.Namespace) -> None:
    if args.concurrency < 1:
        console.print("[red]--concurrency must be >= 1[/]")
        sys.exit(2)
    if args.timeout <= 0:
        console.print("[red]--timeout must be > 0[/]")
        sys.exit(2)
    if args.retries < 0:
        console.print("[red]--retries must be >= 0[/]")
        sys.exit(2)


def main() -> None:
    args = build_parser().parse_args()
    validate_args(args)

    source = None if args.file == "-" else Path(args.file)
    urls = load_urls(source)

    follow_note = (
        "[bold cyan]following redirects[/]"
        if args.follow_redirects
        else "[bold yellow]not following redirects[/] (3xx reported as-is)"
    )

    started = time.perf_counter()
    try:
        results = asyncio.run(
            run_checks(
                urls,
                follow=args.follow_redirects,
                timeout=args.timeout,
                concurrency=args.concurrency,
                retries=args.retries,
                user_agent=args.user_agent,
                insecure=args.insecure,
                method_note=follow_note,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/]")
        sys.exit(130)

    wall = time.perf_counter() - started
    render_results(
        results,
        follow=args.follow_redirects,
        show_redirects=args.show_redirects,
        only=args.only,
    )
    render_summary(results, wall)

    if args.json_out:
        export_json(results, Path(args.json_out))
    if args.csv_out:
        export_csv(results, Path(args.csv_out))

    # Non-zero exit if anything was unreachable or returned 5xx.
    hard_fail = any(r.family in {"error", "5xx"} for r in results)
    sys.exit(1 if hard_fail else 0)


if __name__ == "__main__":
    main()
