"""Interactive WebHawk console.

Bare `webhawk` in a terminal opens this prompt. `use` selects a module.
`set` stores that module's options, and `run` executes them. Typing a
module name runs it once and returns to the prompt.
"""

from __future__ import annotations

import random
import shlex
from collections.abc import Callable
from pathlib import Path

from rich.markup import escape
from rich.table import Table

from hawk import VERSION, ui
from hawk.catalog import REFERENCES, locate_script, reference_canonical
from hawk.modules import MODULES
from hawk.complete import (
    CompleteState,
    history_path,
    install_reader,
    load_history,
    save_history,
    sensitive_line,
    suggest_console,
)
from hawk.loader import ScanMain, run_named
from hawk.options import prepare_argv, print_settings, set_option, show_options, unset_option

ReadLine = Callable[[str], str]
Runner = Callable[..., int]
Prepare = Callable[..., list[str]]

# Startup art. Each one spells WEBHAWK. print_banner picks a new one every call.
BANNERS = (
    r"""
W   W EEEEE BBBB  H   H  AAA  W   W K   K
W   W E     B   B H   H A   A W   W K  K 
W W W EEE   BBBB  HHHHH AAAAA W W W KKK  
W W W E     B   B H   H A   A W W W K  K 
 W W  EEEEE BBBB  H   H A   A  W W  K   K
""".strip("\n"),
    r"""
__      __  ___   ___   _  _   ___  __      __  _  __
\ \    / / | __| | _ ) | || | /   \ \ \    / / | |/ /
 \ \/\/ /  | _|  | _ \ | __ | |___|  \ \/\/ /  | ' < 
  \_/\_/   |___| |___/ |_||_| |   |   \_/\_/   |_|\_\
""".strip("\n"),
    r"""
_   _ ____ ___  _  _  /\  _   _ _  _
| | | |__  |__] |__| /__\ | | | |_/ 
|_|_| |___ |__] |  | |  | |_|_| | \_
""".strip("\n"),
    r"""
W    W EEEEEE BBBBB  HH  HH  AAAA  W    W KK  KK
W WW W EE     BB  BB HH  HH AA  AA W WW W KKKK  
WW  WW EEEE   BBBBB  HHHHHH AAAAAA WW  WW KK KK 
W    W EEEEEE BB  BB HH  HH AA  AA W    W KK  KK
""".strip("\n"),
    r"""
W   W EEEEE BBBB  H   H  AAA  W   W K   K        
  W   W E     B   B H   H A   A W   W K  K       
    W W W EEE   BBBB  HHHHH AAAAA W W W KKK      
      W W W E     B   B H   H A   A W W W K  K   
         W W  EEEEE BBBB  H   H A   A  W W  K   K
""".strip("\n"),
)

_last_banner = -1


def canonical_module(token: str) -> str | None:
    if token == "scan":
        return "scan"
    return reference_canonical(token)


def print_loadable(tool_file: Path) -> None:
    table = Table(title="modules", header_style="brand", box=None, pad_edge=False)
    table.add_column("Module", style="info")
    table.add_column("State")
    table.add_column("What it does")
    table.add_row("scan", "[ok]ready[/ok]", "Map HTTP/HTTPS attack surface.")
    for name, summary in MODULES.items():
        table.add_row(name, "[ok]ready[/ok]", summary)
    for tool in REFERENCES:
        ready = locate_script(tool, tool_file) is not None
        state = "[ok]ready[/ok]" if ready else "[muted]not on disk[/muted]"
        label = tool.command
        if tool.aliases:
            label = f"{tool.command} ({', '.join(tool.aliases)})"
        table.add_row(label, state, tool.summary)
    ui.console.print(table)
    ui.console.print("\n[info]use[/info] <module> selects one. [info]run[/info] <args> executes it.")
    ui.console.print("A module name also runs immediately: [info]pulse urls.txt[/info]")
    ui.console.print("[info]search[/info] <word> finds a module by name or description.")


def choose_banner() -> str:
    """Pick a banner other than the one shown last."""
    global _last_banner
    pool = [index for index in range(len(BANNERS)) if index != _last_banner]
    _last_banner = random.choice(pool)
    return BANNERS[_last_banner]


def print_banner() -> None:
    art = choose_banner()
    width = ui.console.size.width if ui.console.size else 80
    longest = max(len(line) for line in art.splitlines())
    if width >= longest + 2:
        ui.console.print(art, style="brand", markup=False, highlight=False)
    else:
        ui.console.print("[brand]WEBHAWK[/brand]")
    ui.console.print(f"\n[brand]WebHawk {VERSION}[/brand]  [muted]authorized HTTP toolkit[/muted]")
    ui.console.print(
        "\n[info]help[/info]            command guide\n"
        "[info]show modules[/info]    what you can load\n"
        "[info]use[/info] <module>    select one, then [info]show options[/info]\n"
        "[info]set[/info] NAME VALUE  save a flag, then [info]run[/info]\n"
        "[info]exit[/info]            leave the console\n"
        "[info]Tab[/info]             completes commands, modules, and options"
    )


def print_console_help(active: str | None) -> None:
    ui.console.print(
        "[info]help[/info]            this guide\n"
        "[info]show modules[/info]    list modules\n"
        "[info]use[/info] <module>    select a module\n"
        "[info]show options[/info]    flags for the selected module\n"
        "[info]set[/info] NAME VALUE  save a flag for later runs ([info]set[/info] NAME=VALUE works too)\n"
        "[info]unset[/info] NAME      forget one saved flag, or [info]unset all[/info]\n"
        "[info]run[/info] <args>      run the module; saved flags fill the gaps\n"
        "[info]back[/info]            clear the selection\n"
        "[info]banner[/info]          show a different banner\n"
        "[info]search[/info] <word>   find a module by name or description\n"
        "[info]history[/info]         recent commands from this session\n"
        "[info]doctor[/info]          check Python and packages\n"
        "[info]version[/info]         print the WebHawk version\n"
        "[info]exit[/info]            leave the console\n"
        "\n[info]Tab[/info] completes commands, modules, option names, and paths.\n"
        "Up and down recall history in a terminal.\n"
        "\nThe same module from the shell, without the prompt:\n"
        "  webhawk pulse urls.txt --follow-redirects\n"
        "  webhawk ct example.com -c\n"
        "  webhawk tcurl example.com -I\n"
        "  webhawk repeater captured.http --print"
    )
    if active:
        ui.console.print(
            f"\nSelected module: [info]{escape(active)}[/info]. "
            "[info]show options[/info] lists its flags."
        )


def print_module_search(query: str) -> None:
    needle = query.strip().lower()
    if not needle:
        ui.console.print("[info]search[/info] <word> matches module names and descriptions.")
        return
    rows: list[tuple[str, str]] = []
    scan = ("scan", "Map HTTP/HTTPS attack surface.")
    if needle in scan[0] or needle in scan[1].lower():
        rows.append(scan)
    for name, summary in MODULES.items():
        if needle in name or needle in summary.lower():
            rows.append((name, summary))
    for tool in REFERENCES:
        hay = " ".join([tool.command, *tool.aliases, tool.summary]).lower()
        if needle in hay:
            rows.append((tool.command, tool.summary))
    if not rows:
        ui.console.print(f"No module matches [warn]{escape(query.strip())}[/warn].")
        ui.console.print("[info]show modules[/info] lists all of them.")
        return
    for name, summary in rows:
        ui.console.print(f"[info]{name}[/info]  {summary}")


def print_history(lines: list[str]) -> None:
    if not lines:
        ui.console.print("No commands yet. Up and down recall lines in a terminal.")
        return
    shown = lines[-40:]
    start = len(lines) - len(shown) + 1
    for number, line in enumerate(shown, start):
        ui.console.print(f"[muted]{number:>4}[/muted]  {escape(line)}", highlight=False)


def _prompt(active: str | None) -> str:
    if active:
        return f"webhawk {active} > "
    return "webhawk > "


def run_console(
    *,
    tool_file: Path,
    scan_main: ScanMain,
    read_line: ReadLine | None = None,
    run_module: Runner | None = None,
    build_parser=None,
    merge_argv: Prepare | None = None,
) -> int:
    """Read commands until `exit` or EOF. Returns 0 when the user leaves."""
    runner = run_module or run_named
    merge = merge_argv or prepare_argv
    active: str | None = None
    settings: dict[str, dict[str, str]] = {}
    state = CompleteState(tool_file, build_parser, settings)
    transcript: list[str] = []
    remember = False
    if read_line is None:
        hooked = install_reader(state)
        reader = hooked or input
        if hooked is not None:
            remember = True
            transcript.extend(load_history(history_path()))
    else:
        reader = read_line
    print_banner()
    try:
        while True:
            state.active = active
            try:
                line = reader(_prompt(active))
            except EOFError:
                ui.console.print("")
                return 0
            except KeyboardInterrupt:
                ui.console.print("\n[warn]Type exit to leave the console.[/warn]")
                continue
            if line is None:
                return 0
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                parts = shlex.split(stripped)
            except ValueError as exc:
                ui.console.print(f"[err]Could not parse that line:[/err] {escape(str(exc))}")
                continue
            if not parts:
                continue
            should_leave, active = _dispatch_line(
                parts,
                active,
                tool_file,
                scan_main,
                runner,
                settings,
                build_parser,
                merge,
                transcript,
            )
            if stripped and not sensitive_line(stripped):
                transcript.append(stripped)
                if remember:
                    import readline

                    readline.add_history(stripped)
            if should_leave:
                return 0
    finally:
        if remember:
            save_history(history_path(), transcript)


def _dispatch_line(
    parts: list[str],
    active: str | None,
    tool_file: Path,
    scan_main: ScanMain,
    runner: Runner,
    settings: dict[str, dict[str, str]],
    build_parser,
    merge: Prepare,
    transcript: list[str],
) -> tuple[bool, str | None]:
    head, *rest = parts
    if head in ("exit", "quit"):
        return True, active
    if head in ("help", "?"):
        print_console_help(active)
        return False, active
    if head == "banner":
        print_banner()
        return False, active
    if head == "search":
        print_module_search(" ".join(rest))
        return False, active
    if head == "history":
        print_history(transcript)
        return False, active
    if head == "show":
        topic = rest[0] if rest else "modules"
        if topic in ("modules", "module"):
            print_loadable(tool_file)
        elif topic == "options":
            if active is None:
                ui.console.print("No module is selected. [info]use[/info] one, then [info]show options[/info].")
            else:
                show_options(active, settings.setdefault(active, {}), tool_file=tool_file, build_parser=build_parser)
        else:
            ui.console.print("Try [info]show modules[/info] or [info]show options[/info].")
        return False, active
    if head == "set":
        if active is None:
            ui.console.print("No module is selected. [info]use[/info] one, then [info]set[/info] NAME VALUE.")
            return False, active
        saved = settings.setdefault(active, {})
        if not rest:
            print_settings(active, saved)
        elif len(rest) == 1 and "=" in rest[0]:
            key, value = rest[0].split("=", 1)
            if not value:
                ui.console.print("[info]set[/info] NAME VALUE. [info]show options[/info] lists names.")
            else:
                set_option(active, saved, key, value, tool_file=tool_file, build_parser=build_parser)
        elif len(rest) == 1:
            ui.console.print("[info]set[/info] NAME VALUE. [info]show options[/info] lists names.")
        else:
            set_option(
                active,
                saved,
                rest[0],
                " ".join(rest[1:]),
                tool_file=tool_file,
                build_parser=build_parser,
                tokens=rest[1:],
            )
        return False, active
    if head == "unset":
        if active is None:
            ui.console.print("No module is selected.")
            return False, active
        if not rest:
            ui.console.print("[info]unset[/info] NAME, or [info]unset all[/info].")
        else:
            unset_option(settings.setdefault(active, {}), rest[0])
        return False, active
    if head in ("modules", "commands"):
        print_loadable(tool_file)
        return False, active
    if head == "version":
        ui.console.print(f"WebHawk {VERSION}")
        return False, active
    if head == "doctor":
        from hawk.doctor import run as run_doctor

        run_doctor(tool_file)
        return False, active
    if head == "examples":
        from hawk.cli import print_examples

        print_examples()
        return False, active
    if head == "back":
        if active is None:
            ui.console.print("No module is selected.")
        return False, None
    if head == "use":
        return False, _use(rest, active)
    if head == "run":
        if active is None:
            ui.console.print("No module is selected. [info]show modules[/info], then [info]use[/info] one.")
            return False, active
        _invoke(runner, active, rest, tool_file, scan_main, settings, build_parser, merge)
        return False, active
    chosen = canonical_module(head)
    if chosen:
        _invoke(runner, chosen, rest, tool_file, scan_main, settings, build_parser, merge)
        return False, active
    from hawk.cli import suggest_command

    guess = suggest_console(head) or suggest_command(head)
    if guess:
        ui.console.print(f"Unknown command [warn]{escape(head)}[/warn]. Did you mean [info]{escape(guess)}[/info]?")
        return False, active
    if active:
        ui.console.print(
            f"Unknown command [warn]{escape(head)}[/warn]. "
            f"Run {escape(active)} with [info]run[/info] <args>."
        )
    else:
        ui.console.print(f"Unknown command [warn]{escape(head)}[/warn]. Type [info]help[/info].")
    return False, active


def _use(rest: list[str], active: str | None) -> str | None:
    if len(rest) != 1:
        ui.console.print("[info]use[/info] takes one module name. [info]show modules[/info] lists them.")
        return active
    chosen = canonical_module(rest[0])
    if chosen is None:
        from hawk.cli import suggest_command

        guess = suggest_command(rest[0])
        if guess and canonical_module(guess):
            ui.console.print(
                f"Unknown module [warn]{escape(rest[0])}[/warn]. Did you mean [info]{escape(guess)}[/info]?"
            )
        else:
            ui.console.print(f"Unknown module [warn]{escape(rest[0])}[/warn]. [info]show modules[/info] lists them.")
        return active
    ui.console.print(
        f"Using [info]{escape(chosen)}[/info]. "
        "[info]show options[/info], [info]set[/info], then [info]run[/info]. [info]back[/info] clears the selection."
    )
    return chosen


def _invoke(
    runner: Runner,
    name: str,
    argv: list[str],
    tool_file: Path,
    scan_main: ScanMain,
    settings: dict[str, dict[str, str]],
    build_parser,
    merge: Prepare,
) -> None:
    saved = settings.get(name, {})
    merged = merge(name, argv, saved, tool_file=tool_file, build_parser=build_parser)
    if merged:
        ui.console.print(f"webhawk {name} {shlex.join(merged)}", markup=False, highlight=False)
    try:
        code = runner(name, merged, tool_file=tool_file, scan_main=scan_main)
    except KeyboardInterrupt:
        ui.console.print("\n[warn]Interrupted.[/warn]")
        code = 130
    if code:
        ui.console.print(f"[muted]exit {code}[/muted]")
