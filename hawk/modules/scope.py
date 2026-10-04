"""Scope workspace commands."""

from __future__ import annotations

import argparse
from pathlib import Path

from rich.markup import escape

from hawk import ui
from hawk.workspace import (
    add_entries,
    allowed,
    explain_block,
    hostname_of,
    init_workspace,
    read_entries,
    read_urls,
    remember_urls,
    remove_entries,
    scope_is_active,
    urls_path,
    workspace_dir,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webhawk scope",
        description="Keep the hosts this engagement may touch, and the URL list other modules share.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Create .webhawk with an empty scope.")
    sub.add_parser("path", help="Print the workspace directory.")
    sub.add_parser("list", help="Print scope entries.")
    added = sub.add_parser("add", help="Add hosts, domains, *.domains, or CIDRs.")
    added.add_argument("hosts", nargs="+", help="Host, domain, *.domain, CIDR, or URL.")
    removed = sub.add_parser("remove", help="Remove scope entries.")
    removed.add_argument("hosts", nargs="+")
    check = sub.add_parser("allow", help="Exit 0 when the host is in scope.")
    check.add_argument("target", help="Host or URL.")
    imported = sub.add_parser("import-urls", help="Keep in-scope URLs from a file.")
    imported.add_argument("file", help="One URL per line.")
    sub.add_parser("urls", help="Print the shared URL list.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    command = args.command
    if command == "init":
        root = init_workspace()
        ui.console.print(f"[ok]scope[/ok] {root}", markup=False, highlight=False)
        return 0
    if command == "path":
        ui.console.print(str(workspace_dir()), markup=False, highlight=False)
        return 0
    if command == "list":
        return _list()
    if command == "add":
        return _add(args.hosts)
    if command == "remove":
        return _remove(args.hosts)
    if command == "allow":
        return _allow(args.target)
    if command == "import-urls":
        return _import_urls(args.file)
    if command == "urls":
        for url in read_urls():
            print(url)
        return 0
    ui.console.print("[err]Unknown scope command.[/err]")
    return 2


def _list() -> int:
    root = workspace_dir()
    if not scope_is_active():
        ui.console.print("No scope file yet.")
        ui.console.print("  webhawk scope init")
        return 2
    entries = read_entries()
    ui.console.print(str(root), markup=False, highlight=False)
    if not entries:
        ui.console.print("Scope is empty. Loopback is still allowed.")
    for entry in entries:
        ui.console.print(entry, markup=False, highlight=False)
    ui.console.print(f"{len(read_urls())} URL(s) in {urls_path().name}")
    return 0


def _add(hosts: list[str]) -> int:
    try:
        added, already = add_entries(hosts)
    except ValueError as exc:
        ui.console.print(f"[err]{escape(str(exc))}[/err]")
        return 2
    for entry in added:
        ui.console.print(f"[ok]added[/ok] {entry}", markup=False)
    for entry in already:
        ui.console.print(f"[muted]already in scope[/muted] {entry}", markup=False)
    return 0


def _remove(hosts: list[str]) -> int:
    try:
        removed, missing = remove_entries(hosts)
    except ValueError as exc:
        ui.console.print(f"[err]{escape(str(exc))}[/err]")
        return 2
    for entry in removed:
        ui.console.print(f"[ok]removed[/ok] {entry}", markup=False)
    for entry in missing:
        ui.console.print(f"[warn]not in scope[/warn] {entry}", markup=False)
    return 0 if removed else 2


def _allow(target: str) -> int:
    host = hostname_of(target) or target.strip()
    if allowed(target):
        ui.console.print(f"[ok]in scope[/ok] {host}", markup=False)
        return 0
    ui.console.print(explain_block(host), markup=False, highlight=False)
    return 2


def _import_urls(file_name: str) -> int:
    path = Path(file_name)
    if not path.is_file():
        ui.console.print(f"[err]No file named[/err] {file_name}", markup=False)
        return 2
    if not scope_is_active():
        ui.console.print(explain_block("(no host)"), markup=False, highlight=False)
        return 2
    kept: list[str] = []
    skipped = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        if "://" not in text:
            skipped += 1
            continue
        if allowed(text):
            kept.append(text)
        else:
            skipped += 1
    unique: list[str] = []
    seen: set[str] = set()
    for url in kept:
        if url in seen:
            continue
        seen.add(url)
        unique.append(url)
    fresh = remember_urls(unique)
    for url in unique:
        print(url)
    ui.console.print(f"[ok]{fresh} new[/ok]  {len(unique)} in scope  {skipped} skipped")
    return 0
