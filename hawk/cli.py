"""Route `webhawk` arguments.

The first token is a command only when it is one of the reserved names.
Anything else, including flags, is a scan. That keeps

    webhawk 127.0.0.1 --ports 80,443

on the same path it had before the shell existed.

A host that is literally named like a command is scanned with either form:

    webhawk scan modules
    webhawk -- modules

No arguments in a terminal opens the console. `webhawk pulse urls.txt`
runs that module once and exits.
"""

from __future__ import annotations

import difflib
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from hawk import VERSION, ui
from hawk.catalog import (
    BUILTIN_SUMMARIES,
    REFERENCES,
    addon_roots,
    locate_script,
    reference_canonical,
    tool_by_command,
)
from hawk.modules import MODULES

ScanMain = Callable[..., int]
BuildParser = Callable[[str], object]

SHELLS = ("bash", "zsh")


@dataclass(frozen=True)
class Route:
    command: str
    args: list[str]
    # True when the user typed the word `scan`, so help can say `webhawk scan`.
    scan_verb: bool = False
    token: str = ""
    suggestion: str = ""


def _suggestion_pool() -> dict[str, str]:
    """Map a typo target to the command we would run."""
    pool = {
        "scan": "scan",
        "console": "console",
        "modules": "modules",
        "commands": "modules",
        "doctor": "doctor",
        "examples": "examples",
        "completion": "completion",
        "version": "version",
        "help": "help",
    }
    for name in MODULES:
        pool[name] = name
    for tool in REFERENCES:
        pool[tool.command] = tool.command
    return pool


def suggest_command(token: str) -> str | None:
    """Return a canonical command for a near-miss, or None.

    Tokens that look like hosts, URLs, CIDRs, or flags are left alone so
    `localhost` and `app.internal` keep scanning.
    """
    if not token or token.startswith("-") or any(ch in token for ch in "./:"):
        return None
    if token.isdigit():
        return None
    pool = _suggestion_pool()
    match = difflib.get_close_matches(token, pool.keys(), n=1, cutoff=0.8)
    if not match or match[0] == token:
        return None
    return pool[match[0]]


_BUILTIN_ROUTES = {
    "scan": "scan",
    "console": "console",
    "modules": "modules",
    "commands": "modules",
    "doctor": "doctor",
    "examples": "examples",
    "completion": "completion",
}


def route_argv(argv: list[str]) -> Route:
    if not argv:
        return Route("help-usage", [])
    head, *rest = argv
    if head == "--":
        return Route("scan", rest, scan_verb=False)
    if head in ("-h", "--help", "help"):
        return Route("help", rest)
    if head in ("-V", "--version", "version"):
        return Route("version", rest)
    if head in _BUILTIN_ROUTES:
        return Route(_BUILTIN_ROUTES[head], rest, scan_verb=(head == "scan"), token=head)
    # Module names run that tool. They must not fall through to a scan.
    if reference_canonical(head):
        return Route("module", rest, token=head)
    guessed = suggest_command(head)
    if guessed:
        return Route("suggest", rest, token=head, suggestion=guessed)
    return Route("scan", list(argv), scan_verb=False)


def _scan_flag_names(build_parser: BuildParser) -> list[str]:
    parser = build_parser("webhawk")
    names: list[str] = []
    for action in getattr(parser, "_actions", ()):
        for opt in getattr(action, "option_strings", ()):
            names.append(opt)
    return names


def print_overview(*, usage_error: bool) -> int:
    from rich.table import Table

    ui.console.print(f"[brand]WebHawk {VERSION}[/brand]  authorized HTTP toolkit")
    ui.console.print(
        "In a terminal, [info]webhawk[/info] with no arguments opens the console.\n"
        "  [info]use pulse[/info]\n"
        "  [info]show options[/info]\n"
        "  [info]set FILE urls.txt[/info]\n"
        "  [info]run[/info]\n"
        "The default command is still [info]scan[/info]. "
        "Pass a target or a scan flag and WebHawk maps that host.\n"
        "  [info]webhawk 127.0.0.1 --ports 80,443 --intel[/info]\n"
        "  [info]webhawk pulse urls.txt[/info]\n"
        "  [info]webhawk scope init[/info]\n"
        "  [info]webhawk repeater request.txt --print[/info]"
    )
    table = Table(header_style="brand", show_lines=False, box=None, pad_edge=False)
    table.add_column("Command", style="info")
    table.add_column("What it does")
    for name in ("scan", "console", "modules", "doctor", "examples", "completion", "version", "help"):
        table.add_row(name, BUILTIN_SUMMARIES[name])
    ui.console.print(table)
    ui.console.print(
        "\n[info]Often-used scan flags[/info]\n"
        "  --ports SPEC       80,443,8000-8010\n"
        "  -l FILE            hosts, one per line\n"
        "  --output-dir DIR   live.txt, pages/, headers/, JSON, CSV, Markdown\n"
        "  --intel            discover + header score + JS + favicon + DNS\n"
        "  --authorized       required for wide ports, big CIDRs, and huge path sets\n"
        "  --md FILE          findings report\n"
        "\nEvery scan flag: [info]webhawk scan --help[/info]\n"
        "Modules: [info]webhawk modules[/info]    Console help: [info]webhawk help console[/info]\n"
        "A host whose name is a command: [info]webhawk scan modules[/info]  or  [info]webhawk -- modules[/info]"
    )
    if usage_error:
        ui.console.print("\n[err]No command or target was given.[/err]")
        return 2
    return 0


def print_examples() -> int:
    ui.console.print(
        f"[brand]WebHawk {VERSION}[/brand] examples\n\n"
        "[info]# lab host, common web ports[/info]\n"
        "webhawk 127.0.0.1\n\n"
        "[info]# write live URLs, bodies, headers, and reports together[/info]\n"
        "webhawk scan 127.0.0.1 --ports 80,443,8080 --output-dir ./hawk-out\n\n"
        "[info]# authorized recon pack[/info]\n"
        "webhawk app.internal --ports 80,443 --https-only --insecure \\\n"
        "    --delay 0.4-1.2 --intel --cors --ct --banners --md hawk.md\n\n"
        "[info]# lists that ship with the repo[/info]\n"
        "webhawk 127.0.0.1 --user-agent agents.example.txt --rotate-agent \\\n"
        "    --paths paths.example.txt --headers-file headers.example.txt\n\n"
        "[info]# a file of hosts is -l, not a positional target[/info]\n"
        "webhawk -l targets.example.txt --only-live\n\n"
        "[info]# console: pick a module, set its flags, then run[/info]\n"
        "webhawk\n"
        "use pulse\n"
        "show options\n"
        "set FILE urls.txt\n"
        "set FOLLOW_REDIRECTS true\n"
        "run\n"
        "exit\n\n"
        "[info]# the same module as one command[/info]\n"
        "webhawk pulse urls.txt\n"
        "webhawk ct example.com -c -o live.txt\n"
        "webhawk tcurl --help\n\n"
        "[info]# scope, robots, and repeater[/info]\n"
        "webhawk scope init\n"
        "webhawk scope add app.internal\n"
        "webhawk robots robots.txt --base https://app.internal\n"
        "webhawk repeater request.txt --method POST --path /api --print\n\n"
        "[info]# shell setup[/info]\n"
        "webhawk doctor\n"
        "webhawk modules\n"
        "webhawk completion bash > ~/.local/share/bash-completion/completions/webhawk\n"
        "webhawk completion zsh > ~/.zsh/completions/_webhawk"
    )
    return 0


def print_modules(tool_file: Path) -> int:
    from rich.table import Table

    table = Table(title="commands", header_style="brand")
    table.add_column("Command", style="info")
    table.add_column("State")
    table.add_column("What it does")
    for name in ("scan", "console", "modules", "doctor", "examples", "completion", "version", "help"):
        table.add_row(name, "[ok]built-in[/ok]", BUILTIN_SUMMARIES[name])
    for name, summary in MODULES.items():
        table.add_row(name, "[ok]built-in[/ok]", summary)
    for tool in REFERENCES:
        script = locate_script(tool, tool_file)
        state = "[ok]module[/ok]" if script else "[muted]not on disk[/muted]"
        table.add_row(tool.command, state, tool.summary)
    ui.console.print(table)

    ui.console.print(
        "\n[info]Console[/info]\n"
        "  webhawk\n"
        "  use pulse\n"
        "  show options\n"
        "  set FILE urls.txt\n"
        "  run\n"
        "\n[info]One-shot[/info]\n"
        "  webhawk pulse urls.txt\n"
        "  webhawk ct example.com -c\n"
        "  webhawk scope add app.internal\n"
        "  webhawk repeater request.txt --print"
    )
    ui.console.print("\n[muted]Module search path[/muted] (first hit wins; override with WEBHAWK_ADDONS)")
    for root in addon_roots(tool_file):
        ui.console.print(f"  {root}", markup=False, crop=False, no_wrap=True, overflow="ignore")
    shown = False
    for tool in REFERENCES:
        script = locate_script(tool, tool_file)
        if script is None:
            continue
        if not shown:
            ui.console.print("\n[muted]Module files[/muted]")
            shown = True
        ui.console.print(
            f"  {tool.command:<8} {script}",
            markup=False,
            crop=False,
            no_wrap=True,
            overflow="ignore",
        )
    ui.console.print(
        "\nThese names are modules, so [info]webhawk pulse[/info] runs pulse.\n"
        "To scan a host that is literally named pulse: [info]webhawk scan pulse[/info] or [info]webhawk -- pulse[/info]."
    )
    return 0


def _canonical_reserved(token: str) -> str:
    return reference_canonical(token) or token


def print_module_topic(token: str, tool_file: Path) -> int:
    """Help for one module. Does not run it."""
    canonical = _canonical_reserved(token) or token
    if canonical in MODULES:
        ui.console.print(f"[info]{canonical}[/info]  {MODULES[canonical]}")
        ui.console.print(f"\n  webhawk {canonical} \\[args]")
        ui.console.print(f"  webhawk {canonical} --help")
        ui.console.print("\nIn the console:")
        ui.console.print(f"  use {canonical}")
        ui.console.print("  show options")
        ui.console.print("  set NAME VALUE")
        ui.console.print("  run \\[args]")
        return 0
    tool = tool_by_command(canonical)
    if tool is None:
        ui.console.print(f"[err]No module named[/err] {token}")
        return 2
    ui.console.print(f"[info]{tool.command}[/info]  {tool.summary}")
    if tool.aliases:
        ui.console.print("Also: " + ", ".join(tool.aliases))
    ui.console.print(f"\n  webhawk {tool.command} \\[args]")
    ui.console.print(f"  webhawk {tool.command} --help")
    ui.console.print("\nIn the console:")
    ui.console.print(f"  use {tool.command}")
    ui.console.print("  show options")
    ui.console.print("  set NAME VALUE")
    ui.console.print("  run \\[args]")
    script = locate_script(tool, tool_file)
    if script is None:
        ui.console.print(f"\n[warn]{tool.folder}/{tool.script}[/warn] is not on disk.")
        ui.console.print("Set WEBHAWK_ADDONS, or clone it under ../addons.")
    else:
        ui.console.print("\nProgram:", markup=False)
        ui.console.print(f"  {script}", markup=False, crop=False, no_wrap=True, overflow="ignore")
    return 0


def print_suggestion(token: str, suggestion: str, args: list[str], tool_file: Path) -> int:
    del tool_file
    ui.console.print(f"Unknown command [warn]{token}[/warn]. Did you mean [info]{suggestion}[/info]?")
    if reference_canonical(suggestion):
        ui.console.print(f"  webhawk {suggestion} \\[args]")
    else:
        ui.console.print(f"  webhawk {suggestion}")
    if args:
        ui.console.print("Arguments not forwarded: " + " ".join(args), markup=False)
    ui.console.print(f"To scan a host named {token}:\n  webhawk scan {token}")
    return 2


def print_version() -> int:
    print(f"WebHawk {VERSION}")
    return 0


def command_blurb(command: str) -> str:
    blurbs = {
        "console": (
            "Open the interactive console.\n\n"
            "  webhawk\n"
            "  use pulse\n"
            "  show options\n"
            "  set FILE urls.txt\n"
            "  run\n"
            "  exit\n\n"
            "Tab completes commands, modules, and option names.\n"
            "webhawk console does the same when you want the prompt from a script or a pipe."
        ),
        "modules": "List built-in commands and reference modules.\n\n  webhawk modules",
        "doctor": "Check Python, required packages, and optional ones used by screenshots and reference tools.\n\n  webhawk doctor",
        "examples": "Print copy-paste scans.\n\n  webhawk examples",
        "completion": "Print a completion script.\n\n  webhawk completion bash\n  webhawk completion zsh",
        "version": "Print the version.\n\n  webhawk version\n  webhawk --version",
        "help": "Show the command guide, or help for one command.\n\n  webhawk help\n  webhawk help scan",
    }
    return blurbs.get(command, BUILTIN_SUMMARIES.get(command, command))


def print_completion(shell: str, build_parser: BuildParser) -> int:
    if shell not in SHELLS:
        ui.console.print(f"[err]completion needs one of:[/err] {', '.join(SHELLS)}")
        ui.console.print("  webhawk completion bash")
        return 2
    commands = ["scan", "console", "modules", "commands", "doctor", "examples", "completion", "version", "help"]
    commands.extend(MODULES)
    commands.extend(tool.command for tool in REFERENCES)
    for tool in REFERENCES:
        commands.extend(tool.aliases)
    flags = _scan_flag_names(build_parser)
    if shell == "bash":
        sys.stdout.write(_bash_script(commands, flags))
    else:
        sys.stdout.write(_zsh_script(commands, flags))
    return 0


def _bash_script(commands: list[str], flags: list[str]) -> str:
    command_words = " ".join(commands)
    flag_words = " ".join(flags)
    return f"""# WebHawk {VERSION} bash completion.
# Save it where bash-completion will load it, for example:
#   webhawk completion bash > ~/.local/share/bash-completion/completions/webhawk
_webhawk_complete() {{
  local cur prev
  COMPREPLY=()
  cur="${{COMP_WORDS[COMP_CWORD]}}"
  prev="${{COMP_WORDS[COMP_CWORD-1]}}"
  local commands="{command_words}"
  local flags="{flag_words}"
  if [[ "$COMP_CWORD" -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    return 0
  fi
  if [[ "${{COMP_WORDS[1]}}" == "completion" ]]; then
    COMPREPLY=( $(compgen -W "bash zsh" -- "$cur") )
    return 0
  fi
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
  fi
}}
complete -F _webhawk_complete webhawk
complete -F _webhawk_complete webhawk.py
"""


def _zsh_script(commands: list[str], flags: list[str]) -> str:
    # The file body is the completion function. compinit autoloads a file
    # named `_webhawk`, so this must not wrap itself in another function.
    described = "\n  ".join(f"'{name}'" for name in commands)
    flag_words = " ".join(flags)
    return f"""#compdef webhawk webhawk.py
# WebHawk {VERSION} zsh completion.
# Put this file on fpath after `compinit`:
#   webhawk completion zsh > ~/.zsh/completions/_webhawk
local -a commands
commands=(
  {described}
)
if (( CURRENT == 2 )); then
  _describe 'command' commands
  return
fi
if [[ ${{words[2]}} == completion ]]; then
  _values 'shell' bash zsh
  return
fi
if [[ ${{words[CURRENT]}} == -* ]]; then
  local -a flags
  flags=( {flag_words} )
  _values 'flag' $flags
fi
"""


def _run_scan(scan_main: ScanMain, args: list[str], *, prog: str) -> int:
    try:
        return scan_main(args, prog=prog)
    except SystemExit as exc:
        code = exc.code
        if code is None or code == 0:
            return 0
        if isinstance(code, int):
            return code
        return 1


def _interactive(flag: bool | None) -> bool:
    if flag is not None:
        return flag
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except Exception:
        return False


def dispatch(
    argv: list[str] | None = None,
    *,
    scan_main: ScanMain,
    build_parser: BuildParser,
    tool_file: Path,
    interactive: bool | None = None,
) -> int:
    if argv is None:
        argv = sys.argv[1:]
    else:
        argv = list(argv)
    if not argv and _interactive(interactive):
        from hawk.console import run_console

        return run_console(tool_file=tool_file, scan_main=scan_main, build_parser=build_parser)
    chosen = route_argv(argv)

    if chosen.command == "help-usage":
        return print_overview(usage_error=True)
    if chosen.command == "help":
        topic = chosen.args[0] if chosen.args else ""
        if topic == "commands":
            topic = "modules"
        if topic in ("scan",):
            return _run_scan(scan_main, ["--help"], prog="webhawk scan")
        if topic in ("-h", "--help", ""):
            return print_overview(usage_error=False)
        if topic in BUILTIN_SUMMARIES and topic != "scan":
            ui.console.print(command_blurb(topic if topic != "commands" else "modules"))
            return 0
        canonical = reference_canonical(topic)
        if canonical:
            return print_module_topic(topic, tool_file)
        ui.console.print(f"[err]No help topic for[/err] {topic}")
        ui.console.print("Try [info]webhawk help[/info] or [info]webhawk scan --help[/info].")
        return 2
    if chosen.command == "version":
        return print_version()
    if chosen.command == "modules":
        if chosen.args and chosen.args[0] in ("-h", "--help"):
            ui.console.print(command_blurb("modules"))
            return 0
        return print_modules(tool_file)
    if chosen.command == "doctor":
        if chosen.args and chosen.args[0] in ("-h", "--help"):
            ui.console.print(command_blurb("doctor"))
            return 0
        from hawk.doctor import run as run_doctor

        return run_doctor(tool_file)
    if chosen.command == "examples":
        if chosen.args and chosen.args[0] in ("-h", "--help"):
            ui.console.print(command_blurb("examples"))
            return 0
        return print_examples()
    if chosen.command == "completion":
        if not chosen.args or chosen.args[0] in ("-h", "--help"):
            if chosen.args and chosen.args[0] in ("-h", "--help"):
                ui.console.print(command_blurb("completion"))
                return 0
            return print_completion("", build_parser)
        return print_completion(chosen.args[0], build_parser)
    if chosen.command == "console":
        if chosen.args and chosen.args[0] in ("-h", "--help"):
            ui.console.print(command_blurb("console"))
            return 0
        if chosen.args:
            ui.console.print("[err]console takes no arguments.[/err]")
            ui.console.print("  webhawk console")
            return 2
        from hawk.console import run_console

        return run_console(tool_file=tool_file, scan_main=scan_main, build_parser=build_parser)
    if chosen.command == "module":
        from hawk.loader import run_named

        return run_named(chosen.token, chosen.args, tool_file=tool_file, scan_main=scan_main)
    if chosen.command == "suggest":
        return print_suggestion(chosen.token, chosen.suggestion, chosen.args, tool_file)
    prog = "webhawk scan" if chosen.scan_verb else "webhawk"
    return _run_scan(scan_main, chosen.args, prog=prog)


def entry(argv: list[str] | None = None) -> None:
    """Console-script entry. Imports the scanner, then routes."""
    from webhawk import main

    try:
        code = main(argv)
    except KeyboardInterrupt:
        code = 130
    raise SystemExit(code)
