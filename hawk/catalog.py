"""Built-in commands and reference modules.

Reference tools stay separate programs. The loader imports each clone and
calls its ``main``. ``modules`` reports whether that program is on disk.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from hawk.modules import MODULES


@dataclass(frozen=True)
class ReferenceTool:
    command: str
    summary: str
    folder: str
    script: str
    aliases: tuple[str, ...] = ()


REFERENCES: tuple[ReferenceTool, ...] = (
    ReferenceTool(
        "pulse",
        "Parallel URL liveness, grouped by status family.",
        "pulse",
        "pulse.py",
    ),
    ReferenceTool(
        "ct",
        "Certificate-transparency subdomains, live check, and a wordlist.",
        "crt-scout",
        "crt-scout.py",
        aliases=("crt-scout",),
    ),
    ReferenceTool(
        "carve",
        "Pull links out of HAR files, mitmproxy dumps, HTML, and JS.",
        "flowcarve",
        "flowcarve.py",
        aliases=("flowcarve",),
    ),
    ReferenceTool(
        "phish",
        "phishunt.io phishing feed, campaigns, and passive URL score.",
        "Lanternjaw",
        "lanternjaw.py",
        aliases=("lanternjaw",),
    ),
    ReferenceTool(
        "ioc",
        "TweetFeed indicators of compromise.",
        "IOCaw",
        "iocaw.py",
        aliases=("iocaw",),
    ),
    ReferenceTool(
        "chroma",
        "abuse.ch malware URLs, hashes, botnet C2s, and SSL certs.",
        "chromahaus",
        "chromahaus.py",
        aliases=("chromahaus",),
    ),
    ReferenceTool(
        "urlscan",
        "urlscan.io search, submit, result, screenshot, and DOM.",
        "urlscan",
        "urlscan.py",
    ),
    ReferenceTool(
        "tcurl",
        "Fetch a URL with curl through Tor and print the exit IP.",
        "tcurl",
        "tcurl",
    ),
    ReferenceTool(
        "skiff",
        "HTTP fuzzer. Replace FUZZ with words from a wordlist.",
        "skiff",
        "skiff.py",
    ),
)

# Display order for `show modules`. Names stay flat: `use silk` is unchanged.
MODULE_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Workspace", ("scope", "session", "roost", "clutch", "blaze", "quill", "snare")),
    (
        "Enumerate",
        (
            "scan",
            "silk",
            "robots",
            "forms",
            "vhost",
            "cert",
            "dns",
            "whois",
            "mail",
            "redirect",
            "pulse",
            "ct",
        ),
    ),
    ("Review", ("repeater", "diff", "jwt", "decode", "carve", "tcurl")),
    ("Watch", ("phish", "ioc", "chroma", "urlscan")),
    ("Probe", ("skiff",)),
)


def group_names() -> list[str]:
    return [title for title, _members in MODULE_GROUPS]


def match_group(token: str) -> str | None:
    """Return the group title for a name, ignoring case."""
    folded = token.strip().lower()
    for title, _members in MODULE_GROUPS:
        if title.lower() == folded:
            return title
    return None


def group_for(name: str) -> str | None:
    for title, members in MODULE_GROUPS:
        if name in members:
            return title
    return None


def _require_group_coverage() -> None:
    seen: list[str] = []
    for _title, members in MODULE_GROUPS:
        seen.extend(members)
    expected = {"scan", *MODULES, *(tool.command for tool in REFERENCES)}
    if len(seen) != len(set(seen)) or set(seen) != expected:
        missing = sorted(expected.difference(seen))
        extra = sorted(set(seen).difference(expected))
        raise RuntimeError(f"module groups drifted: missing {missing} extra {extra}")


_require_group_coverage()

# First argument tokens that must not be treated as scan targets.
# A host with one of these names is scanned with `webhawk scan <name>`
# or `webhawk -- <name>`.
BUILTIN_COMMANDS = (
    "scan",
    "console",
    "modules",
    "commands",
    "doctor",
    "examples",
    "completion",
    "version",
    "help",
)

BUILTIN_SUMMARIES = {
    "scan": "Map HTTP/HTTPS attack surface. This runs when the first argument is a target or a flag.",
    "console": "Open the interactive console. A terminal with no arguments does this too.",
    "modules": "List modules by group. A group name lists that group only.",
    "doctor": "Check the Python version and installed dependencies.",
    "examples": "Print copy-paste scans and shell-setup lines.",
    "completion": "Print a bash or zsh completion script.",
    "version": "Print the WebHawk version.",
    "help": "Show the command guide. `help scan` prints every scan flag.",
}


def alias_map() -> dict[str, str]:
    """Repo-style names that should show the canonical module name."""
    mapping: dict[str, str] = {}
    for tool in REFERENCES:
        for alias in tool.aliases:
            mapping[alias] = tool.command
    return mapping


def reference_canonical(token: str) -> str | None:
    """Return the module command for a built-in, a reference name, or an alias."""
    if token in MODULES:
        return token
    for tool in REFERENCES:
        if token == tool.command or token in tool.aliases:
            return tool.command
    return None


def reserved_names() -> set[str]:
    names = set(BUILTIN_COMMANDS)
    names.update(MODULES)
    for tool in REFERENCES:
        names.add(tool.command)
        names.update(tool.aliases)
    return names


def tool_by_command(name: str) -> ReferenceTool | None:
    for tool in REFERENCES:
        if tool.command == name:
            return tool
    return None


def addon_roots(tool_file: Path) -> list[Path]:
    """Directories that may hold reference clones, most specific first."""
    roots: list[Path] = []
    env = os.environ.get("WEBHAWK_ADDONS", "").strip()
    if env:
        roots.append(Path(env).expanduser())
    repo = tool_file.resolve().parent
    roots.append(repo / "addons")
    roots.append(repo.parent / "addons")
    unique: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        try:
            key = root.resolve()
        except OSError:
            key = root
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    return unique


def locate_script(tool: ReferenceTool, tool_file: Path) -> Path | None:
    for root in addon_roots(tool_file):
        candidate = root / tool.folder / tool.script
        if candidate.is_file():
            return candidate
    return None
