"""Tab completion for the console.

The completer is a pure function so tests can call it without a terminal.
Readline is installed only when stdin and stdout are TTYs.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable
from pathlib import Path

from hawk.catalog import REFERENCES, reference_canonical
from hawk.modules import MODULES
from hawk.options import SpecError, load_spec
from hawk.options import _active_command, _command_from_argv, _find, _visible

CONSOLE_COMMANDS = (
    "help",
    "show",
    "use",
    "set",
    "unset",
    "run",
    "back",
    "banner",
    "doctor",
    "version",
    "examples",
    "modules",
    "search",
    "history",
    "exit",
    "quit",
)

_FILE_NAMES = {"FILE", "INPUTS", "SAVE", "OUTPUT", "WORDLIST", "REQUEST"}
_SENSITIVE = re.compile(r"(token|password|secret|api[_-]?key|authorization)", re.IGNORECASE)
_HISTORY_LIMIT = 1000


class CompleteState:
    """Live console facts the completer reads. `settings` is the session dict."""

    def __init__(self, tool_file: Path, build_parser, settings: dict[str, dict[str, str]]) -> None:
        self.tool_file = tool_file
        self.build_parser = build_parser
        self.settings = settings
        self.active: str | None = None
        self._specs: dict[str, object] = {}

    def spec(self, name: str | None):
        if not name:
            return None
        if name not in self._specs:
            try:
                self._specs[name] = load_spec(name, tool_file=self.tool_file, build_parser=self.build_parser)
            except SpecError:
                self._specs[name] = None
        return self._specs[name]


def module_names() -> list[str]:
    names = ["scan", *MODULES]
    for tool in REFERENCES:
        names.append(tool.command)
        names.extend(tool.aliases)
    return names


def sensitive_line(line: str) -> bool:
    """True when a history line would store a credential."""
    return _SENSITIVE.search(line) is not None


def history_path() -> Path:
    override = os.environ.get("WEBHAWK_HISTORY", "").strip()
    if override:
        return Path(override).expanduser()
    return Path.home() / ".local" / "share" / "webhawk" / "history"


def load_history(path: Path) -> list[str]:
    """Load prior lines into readline and return them. Missing files load as empty."""
    import readline

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines: list[str] = []
    for line in text.splitlines():
        if line and not sensitive_line(line):
            lines.append(line)
    lines = lines[-_HISTORY_LIMIT:]
    for line in lines:
        readline.add_history(line)
    return lines


def save_history(path: Path, lines: list[str]) -> None:
    kept = [line for line in lines if line and not sensitive_line(line)][-_HISTORY_LIMIT:]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    except OSError:
        return


def suggest_console(token: str) -> str | None:
    import difflib

    pool = [name for name in CONSOLE_COMMANDS if name != "?"]
    match = difflib.get_close_matches(token, pool, n=1, cutoff=0.8)
    return match[0] if match else None


def complete_line(prefix: str, word: str, state: CompleteState) -> list[str]:
    """Completions for the token `word`. `prefix` is the line before that token."""
    before = _tokens(prefix)
    if before is None:
        return []
    if not before:
        pool = list(CONSOLE_COMMANDS) + module_names()
        if not word.startswith("?"):
            pool = [item for item in pool if item != "?"]
        return _filter(word, pool)

    head = before[0]
    module = _module_name(head)
    if head == "use" and len(before) == 1:
        return _filter(word, module_names())
    if head == "show" and len(before) == 1:
        return _filter(word, ["modules", "options"])
    if head == "search" and len(before) == 1:
        return _filter(word, module_names())
    if head == "set":
        return _complete_set(before, word, state)
    if head == "unset" and len(before) == 1:
        saved = list(state.settings.get(state.active or "", {}))
        return _filter(word, [*saved, "all"])
    if head == "run":
        return _complete_args(state.active, before[1:], word, state)
    if module and len(before) >= 1:
        return _complete_args(module, before[1:], word, state)
    return []


def install_reader(state: CompleteState) -> Callable[[str], str] | None:
    """Attach the completer. Returns `input`, or None when completion is unavailable."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return None
    try:
        import readline
    except ImportError:
        return None

    matches: list[str] = []

    def completer(text: str, index: int) -> str | None:
        nonlocal matches
        try:
            if index == 0:
                buf = readline.get_line_buffer()
                beg = readline.get_begidx()
                matches = complete_line(buf[:beg], text, state)
            if index < len(matches):
                return matches[index]
        except Exception:
            return None
        return None

    readline.set_completer(completer)
    readline.set_completer_delims(" \t\n")
    readline.parse_and_bind("tab: complete")
    if hasattr(readline, "set_auto_history"):
        readline.set_auto_history(False)
    return input


def path_completions(text: str) -> list[str]:
    """File and directory names for the current token. Directories end with `/`."""
    try:
        return _path_completions(text)
    except OSError:
        return []


def _path_completions(text: str) -> list[str]:
    typed = "~/" if text == "~" else text
    expanded = str(Path(typed).expanduser()) if typed.startswith("~") else typed
    if expanded == "" or expanded.endswith("/"):
        folder = Path(expanded or ".")
        partial = ""
    else:
        folder = Path(expanded).parent
        partial = Path(expanded).name
    if not folder.is_dir():
        return []
    matches: list[str] = []
    for entry in folder.iterdir():
        name = entry.name
        if partial:
            if not name.startswith(partial):
                continue
        elif name.startswith("."):
            continue
        shown = _shown_path(entry, typed)
        if entry.is_dir() and not shown.endswith("/"):
            shown += "/"
        matches.append(shown)
    return sorted(matches, key=str.lower)


def _shown_path(entry: Path, text: str) -> str:
    name = entry.name
    if text.startswith("~/"):
        try:
            relative = entry.resolve().relative_to(Path.home())
        except ValueError:
            return str(entry)
        return "~/" + relative.as_posix()
    if text.endswith("/"):
        return text + name
    if text.startswith("./"):
        parent = Path(text).parent
        shown = name if parent == Path(".") else (parent / name).as_posix()
        if not shown.startswith("./"):
            shown = "./" + shown
        return shown
    if text.startswith("/"):
        return str(entry)
    if "/" in text:
        return (Path(text).parent / name).as_posix()
    return name


def _complete_set(before: list[str], word: str, state: CompleteState) -> list[str]:
    spec = state.spec(state.active)
    if spec is None:
        return []
    saved = state.settings.get(state.active or "", {})
    command = _active_command(spec, saved)
    if len(before) == 1 and "=" in word:
        name, _, value = word.partition("=")
        return [f"{name}={item}" for item in _values(spec, command, name, value)]
    if len(before) == 1:
        return _option_names(spec, command, word)
    if len(before) == 2:
        return _values(spec, command, before[1], word)
    return []


def _complete_args(module: str | None, argv: list[str], word: str, state: CompleteState) -> list[str]:
    spec = state.spec(module)
    if spec is None:
        if word.startswith("-"):
            return []
        return path_completions(word) if word else []
    saved = state.settings.get(module or "", {})
    command = _command_from_argv(spec, argv) or _active_command(spec, saved)
    if word.startswith("-") and "=" in word:
        flag, _, value = word.partition("=")
        opt = _option_for_flag(spec, command, flag)
        if opt is None:
            return []
        return [f"{flag}={item}" for item in _values_for(opt, value)]
    if argv and not word.startswith("-"):
        opt = _option_for_flag(spec, command, argv[-1])
        if opt is not None and opt.kind == "value" and "=" not in argv[-1]:
            return _values_for(opt, word)
    if spec.subcommands and not command and not word.startswith("-"):
        names = [name for name, _help in spec.subcommands]
        matched = _filter(word, names)
        if matched:
            return matched
    if word.startswith("-") or word == "":
        return _flag_names(spec, command, word)
    return path_completions(word)


def _option_names(spec, command: str | None, word: str) -> list[str]:
    want = _norm(word)
    names: list[str] = []
    for opt in _visible(spec, command):
        flag_names = [_norm(flag) for flag in opt.flags]
        if opt.name.startswith(want) or any(flag.startswith(want) for flag in flag_names):
            names.append(opt.name)
    return sorted(set(names), key=str.lower)


def _values(spec, command: str | None, name: str, word: str) -> list[str]:
    opt = _find(spec, name, command)
    if opt is None:
        return []
    return _values_for(opt, word)


def _values_for(opt, word: str) -> list[str]:
    if opt.kind == "bool":
        return _filter(word, ["true", "false"])
    if opt.choices:
        return _filter(word, list(opt.choices))
    if _wants_path(opt, word):
        return path_completions(word)
    return []


def _wants_path(opt, word: str) -> bool:
    if word.startswith(("./", "/", "~")) or "/" in word:
        return True
    return opt.name in _FILE_NAMES or opt.name.endswith("_FILE")


def _flag_names(spec, command: str | None, word: str) -> list[str]:
    flags: list[str] = []
    for opt in _visible(spec, command):
        for flag in opt.flags:
            if word == "" and not flag.startswith("--"):
                continue
            if word == "" or flag.startswith(word):
                flags.append(flag)
    return sorted(set(flags), key=str.lower)


def _option_for_flag(spec, command: str | None, flag: str):
    name = flag.split("=", 1)[0]
    for opt in _visible(spec, command):
        if name in opt.flags:
            return opt
    return None


def _module_name(token: str) -> str | None:
    if token == "scan":
        return "scan"
    return reference_canonical(token)


def _tokens(prefix: str) -> list[str] | None:
    if not prefix.strip():
        return []
    try:
        import shlex

        return shlex.split(prefix)
    except ValueError:
        return None


def _norm(word: str) -> str:
    return word.lstrip("-").upper().replace("-", "_")


def _filter(word: str, choices: list[str]) -> list[str]:
    prefix = word.lower()
    found = {item for item in choices if item.lower().startswith(prefix)}
    return sorted(found, key=str.lower)
