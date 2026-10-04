"""Environment check for the scanner and the reference tools."""

from __future__ import annotations

import importlib.metadata
import shutil
import sys
from dataclasses import dataclass

from hawk import VERSION, ui
from hawk.catalog import REFERENCES, locate_script
from hawk.modules import MODULES


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str
    required: bool


def _dist_version(dist_name: str) -> str | None:
    try:
        return importlib.metadata.version(dist_name)
    except importlib.metadata.PackageNotFoundError:
        return None


def collect_checks(tool_file) -> list[Check]:
    checks: list[Check] = []
    py = sys.version_info
    py_ok = py >= (3, 10)
    checks.append(
        Check(
            "python",
            py_ok,
            f"{py.major}.{py.minor}.{py.micro}  ({sys.executable})",
            required=True,
        )
    )
    for dist, required in (
        ("rich", True),
        ("httpx", True),
        ("playwright", False),
        ("aiohttp", False),
        ("requests", False),
        ("mitmproxy", False),
    ):
        found = _dist_version(dist)
        if found:
            detail = found
            if dist == "playwright":
                detail = f"{found}  (used by --screenshots; run: playwright install chromium)"
            ok = True
        else:
            detail = "not installed"
            ok = False
        checks.append(Check(dist, ok, detail, required=required))

    for binary in ("curl", "torsocks", "tor"):
        found = shutil.which(binary)
        checks.append(
            Check(
                binary,
                bool(found),
                found or "not on PATH  (used by tcurl)",
                required=False,
            )
        )

    found_scripts = 0
    for tool in REFERENCES:
        if locate_script(tool, tool_file) is not None:
            found_scripts += 1
    checks.append(
        Check(
            "reference clones",
            True,
            f"{found_scripts} of {len(REFERENCES)} visible to `webhawk modules`",
            required=False,
        )
    )
    checks.append(
        Check(
            "built-in modules",
            True,
            ", ".join(MODULES),
            required=False,
        )
    )
    checks.append(
        Check(
            "webhawk",
            True,
            f"{VERSION}  ({tool_file})",
            required=False,
        )
    )
    return checks


def render(checks: list[Check]) -> int:
    from rich.table import Table

    table = Table(title=f"webhawk doctor  {VERSION}", header_style="brand", show_lines=False)
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    failed = False
    for check in checks:
        if check.ok:
            status = "[ok]ok[/ok]"
        elif check.required:
            status = "[err]missing[/err]"
            failed = True
        else:
            status = "[warn]optional[/warn]"
        table.add_row(check.name, status, check.detail)
    ui.console.print(table)
    if failed:
        ui.console.print("[err]Required pieces are missing.[/err] Install them with: pip install -r requirements.txt")
        return 1
    ui.console.print("[ok]Scanner dependencies are installed.[/ok]")
    return 0


def run(tool_file) -> int:
    return render(collect_checks(tool_file))
