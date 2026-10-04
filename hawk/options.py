"""Module options for the console.

`show options` reads a tool's argparse parser. `set` stores values for the
session, and `run` fills those in when the command line left them out.
Explicit `run` arguments win.
"""

from __future__ import annotations

import argparse
import shlex
from dataclasses import dataclass

from rich.markup import escape
from rich.table import Table

from hawk import ui
from hawk.catalog import locate_script, reference_canonical, tool_by_command

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


@dataclass(frozen=True)
class Option:
    name: str
    dest: str
    flags: tuple[str, ...]
    kind: str
    required: bool
    help: str
    choices: tuple[str, ...]
    subcommand: str
    repeatable: bool
    store_false: bool
    default: str = ""


@dataclass(frozen=True)
class Spec:
    options: tuple[Option, ...]
    subcommands: tuple[tuple[str, str], ...]
    command_name: str


class SpecError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def load_spec(name: str, *, tool_file, build_parser) -> Spec:
    """Return the option spec for a module, or raise SpecError."""
    if name == "scan":
        if build_parser is None:
            raise SpecError("Scanner options are unavailable.")
        return spec_from_parser(build_parser("webhawk scan"))
    if name == "tcurl":
        return _tcurl_spec()
    canonical = reference_canonical(name) or name
    from hawk.modules import MODULES, load_builtin

    if canonical in MODULES:
        try:
            module = load_builtin(canonical)
        except Exception as exc:
            raise SpecError(f"Could not load {canonical}: {exc}") from exc
        parser = _parser_from_module(module)
        if parser is None:
            raise SpecError(f"{canonical} has no argument parser to read.")
        return spec_from_parser(parser)
    tool = tool_by_command(canonical)
    if tool is None:
        raise SpecError(f"Unknown module {name}.")
    script = locate_script(tool, tool_file)
    if script is None:
        raise SpecError(f"{tool.folder}/{tool.script} is not on disk.")
    from hawk.loader import import_script, looks_like_python

    if not looks_like_python(script):
        raise SpecError(f"{canonical} has no option list.")
    try:
        module = import_script(script)
    except ModuleNotFoundError as exc:
        missing = exc.name or str(exc)
        raise SpecError(f"Missing package: {missing}. Install that tool's requirements, then try again.") from exc
    except Exception as exc:
        raise SpecError(f"Could not load {canonical}: {exc}") from exc
    parser = _parser_from_module(module)
    if parser is None:
        raise SpecError(f"{canonical} has no argument parser to read.")
    return spec_from_parser(parser)


def prepare_argv(name: str, argv: list[str], settings: dict[str, str], *, tool_file, build_parser) -> list[str]:
    """Merge saved settings in front of an explicit run line."""
    if not settings:
        return list(argv)
    try:
        spec = load_spec(name, tool_file=tool_file, build_parser=build_parser)
    except SpecError as exc:
        ui.console.print(f"[warn]Saved options were not applied.[/warn] {escape(exc.message)}")
        return list(argv)
    return render_argv(spec, settings, argv)


def show_options(name: str, settings: dict[str, str], *, tool_file, build_parser) -> None:
    try:
        spec = load_spec(name, tool_file=tool_file, build_parser=build_parser)
    except SpecError as exc:
        ui.console.print(f"[err]{escape(exc.message)}[/err]")
        return
    command = _active_command(spec, settings)
    rows = _visible(spec, command)
    table = Table(title=f"{name} options", header_style="brand", box=None, pad_edge=False)
    table.add_column("Name", style="info")
    table.add_column("Value")
    table.add_column("Required")
    table.add_column("Description")
    for opt in rows:
        current = settings.get(opt.name, "")
        if current:
            shown = escape(current)
        elif opt.default:
            shown = f"[muted]{escape(opt.default)}[/muted]"
        else:
            shown = "·"
        required = "yes" if opt.required else "no"
        table.add_row(opt.name, shown, required, escape(_describe(opt)))
    ui.console.print(table)
    if spec.subcommands and not command:
        names = ", ".join(item[0] for item in spec.subcommands)
        ui.console.print(f"\nSubcommands: {names}", markup=False)
        ui.console.print(f"Set [info]{spec.command_name}[/info] to one of them to see its flags.")
    if any(opt.default and not settings.get(opt.name) for opt in rows):
        ui.console.print("[muted]Dim values are defaults. set stores your own.[/muted]")
    ui.console.print("\n[info]set[/info] NAME VALUE stores a flag. [info]run[/info] fills in the ones you left out.")


def set_option(
    name: str,
    settings: dict[str, str],
    key: str,
    value: str,
    *,
    tool_file,
    build_parser,
    tokens: list[str] | None = None,
) -> bool:
    try:
        spec = load_spec(name, tool_file=tool_file, build_parser=build_parser)
    except SpecError as exc:
        ui.console.print(f"[err]{escape(exc.message)}[/err]")
        return False
    opt = _find(spec, key, _active_command(spec, settings))
    if opt is None:
        want = key.upper().replace("-", "_")
        if sum(1 for item in spec.options if item.name == want) > 1 and spec.command_name:
            ui.console.print(
                f"Set [info]{spec.command_name}[/info] first. {escape(want)} belongs to more than one subcommand."
            )
        else:
            ui.console.print(f"Unknown option [warn]{escape(key)}[/warn]. [info]show options[/info] lists them.")
        return False
    if opt.kind == "bool":
        token = value.lower()
        if token in _TRUE:
            value = "true"
        elif token in _FALSE:
            value = "false"
        else:
            ui.console.print(f"[info]{opt.name}[/info] takes true or false.")
            return False
    elif opt.choices:
        matched = [item for item in opt.choices if item.lower() == value.lower()]
        if len(matched) == 1:
            value = matched[0]
        else:
            ui.console.print(f"[info]{opt.name}[/info] must be one of: {', '.join(opt.choices)}", markup=False)
            return False
    if opt.repeatable or opt.kind == "tail":
        parts = list(tokens) if tokens is not None else shlex.split(value)
        value = shlex.join(parts)
    settings[opt.name] = value
    ui.console.print(f"[info]{opt.name}[/info] => {escape(value)}")
    return True


def unset_option(settings: dict[str, str], key: str) -> None:
    if key.lower() in {"all", "*"}:
        settings.clear()
        ui.console.print("Cleared saved options.")
        return
    want = key.upper().replace("-", "_")
    match = next((name for name in settings if name.upper() == want), None)
    if match is None:
        ui.console.print(f"[warn]{escape(key)}[/warn] is not set.")
        return
    settings.pop(match, None)
    ui.console.print(f"Unset [info]{match}[/info].")


def render_argv(spec: Spec, settings: dict[str, str], argv: list[str]) -> list[str]:
    command = _command_from_argv(spec, argv) or _active_command(spec, settings)
    provided = _provided_dests(spec, argv, command)
    flags: list[str] = []
    leading: list[str] = []
    positionals: list[str] = []
    tail: list[str] = []
    for opt in spec.options:
        if opt.name not in settings:
            continue
        if opt.subcommand and opt.subcommand != (command or ""):
            continue
        if opt.dest in provided:
            continue
        piece = _emit(opt, settings[opt.name])
        if opt.kind == "tail":
            tail.extend(piece)
        elif opt.kind == "positional" and spec.command_name and opt.name == spec.command_name:
            leading.extend(piece)
        elif opt.kind == "positional":
            positionals.extend(piece)
        else:
            flags.extend(piece)
    return leading + flags + list(argv) + positionals + tail


def spec_from_parser(parser: argparse.ArgumentParser, *, subcommand: str = "") -> Spec:
    options: list[Option] = []
    subs: list[tuple[str, str]] = []
    command_name = ""
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction):
            continue
        if isinstance(action, argparse._SubParsersAction):
            command_name = "COMMAND" if action.dest in {"command", "cmd"} else action.dest.upper()
            choice_help = {item.dest: item.help or "" for item in getattr(action, "_choices_actions", ())}
            for choice, child in action.choices.items():
                subs.append((str(choice), choice_help.get(choice, "") or ""))
                nested = spec_from_parser(child, subcommand=str(choice))
                options.extend(nested.options)
            required = bool(getattr(action, "required", False))
            options.append(
                Option(
                    name=command_name,
                    dest=action.dest,
                    flags=(),
                    kind="positional",
                    required=required,
                    help="Subcommand.",
                    choices=tuple(str(item) for item in action.choices),
                    subcommand="",
                    repeatable=False,
                    store_false=False,
                )
            )
            continue
        opt = _option_from_action(action, subcommand)
        if opt is not None:
            options.append(opt)
    return Spec(tuple(options), tuple(subs), command_name)


def _default_note(action: argparse.Action) -> str:
    """Short default for the options table. Empty when there is nothing useful to show."""
    default = getattr(action, "default", None)
    if default is None or default is argparse.SUPPRESS:
        return ""
    if isinstance(
        action,
        (argparse._StoreTrueAction, argparse._StoreFalseAction, argparse._AppendAction, argparse._CountAction),
    ):
        return ""
    if isinstance(default, bool):
        return ""
    text = " ".join(str(default).split())
    if len(text) > 36:
        cut = text[:33]
        space = cut.rfind(" ")
        if space >= 16:
            cut = cut[:space]
        text = cut + "..."
    return text


def _option_from_action(action: argparse.Action, subcommand: str) -> Option | None:
    dest = getattr(action, "dest", None)
    if not dest or dest is argparse.SUPPRESS or dest == "help":
        return None
    if action.help is argparse.SUPPRESS:
        return None
    store_false = isinstance(action, argparse._StoreFalseAction)
    boolean = store_false or isinstance(action, argparse._StoreTrueAction) or (
        getattr(action, "nargs", None) == 0 and isinstance(getattr(action, "const", None), bool)
    )
    positional = not action.option_strings
    repeatable = isinstance(action, argparse._AppendAction) or action.nargs in {"+", "*"}
    if positional:
        kind = "positional"
    elif boolean:
        kind = "bool"
    else:
        kind = "value"
    required = bool(action.required) if not positional else action.nargs not in {"?", "*"}
    choices = tuple(str(item) for item in action.choices) if action.choices else ()
    help_text = "" if action.help in {None, argparse.SUPPRESS} else str(action.help)
    name = dest.upper()
    return Option(
        name=name,
        dest=dest,
        flags=tuple(action.option_strings),
        kind=kind,
        required=required,
        help=help_text,
        choices=choices,
        subcommand=subcommand,
        repeatable=repeatable,
        store_false=store_false,
        default=_default_note(action),
    )


def _tcurl_spec() -> Spec:
    def flag(name: str, *flags: str, help_text: str) -> Option:
        return Option(name, name.lower(), flags, "bool", False, help_text, (), "", False, False)

    options = (
        Option("URL", "url", (), "positional", True, "URL or hostname. A bare hostname is requested as https://.", (), "", False, False),
        flag("NO_PAGER", "--no-pager", "--raw", help_text="Print the response in the terminal instead of less."),
        flag("NO_COLOR", "--no-color", help_text="Plain text."),
        flag("COLOR", "--color", help_text="Color the banner when output is piped."),
        Option("EXTRA", "extra", (), "tail", False, "Extra curl arguments, passed through after the URL.", (), "", True, False),
    )
    return Spec(options, (), "")


def _parser_from_module(module):
    for attr in ("build_parser", "create_parser"):
        factory = getattr(module, attr, None)
        if not callable(factory):
            continue
        try:
            parser = factory()
        except TypeError:
            parser = factory("webhawk")
        if isinstance(parser, argparse.ArgumentParser):
            return parser
    return None


def _visible(spec: Spec, command: str | None) -> list[Option]:
    rows = []
    for opt in spec.options:
        if opt.subcommand and opt.subcommand != (command or ""):
            continue
        rows.append(opt)
    return rows


def _find(spec: Spec, token: str, command: str | None) -> Option | None:
    want = token.upper().replace("-", "_")
    visible = [opt for opt in _visible(spec, command) if opt.name == want]
    if len(visible) == 1:
        return visible[0]
    everywhere = [opt for opt in spec.options if opt.name == want]
    if len(everywhere) == 1:
        return everywhere[0]
    return None


def _active_command(spec: Spec, settings: dict[str, str]) -> str | None:
    if not spec.command_name:
        return None
    return settings.get(spec.command_name) or None


def _command_from_argv(spec: Spec, argv: list[str]) -> str | None:
    if not spec.subcommands:
        return None
    known = {name for name, _help in spec.subcommands}
    for token in argv:
        if token == "--":
            break
        if token.startswith("-"):
            continue
        if token in known:
            return token
    return None


def _provided_dests(spec: Spec, argv: list[str], command: str | None) -> set[str]:
    relevant = [opt for opt in spec.options if not opt.subcommand or opt.subcommand == (command or "")]
    by_flag: dict[str, Option] = {}
    positionals = [opt for opt in relevant if opt.kind == "positional"]
    for opt in relevant:
        for flag in opt.flags:
            by_flag[flag] = opt
    seen: set[str] = set()
    pos_index = 0
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--":
            index += 1
            while index < len(argv) and pos_index < len(positionals):
                seen.add(positionals[pos_index].dest)
                pos_index += 1
                index += 1
            break
        if token.startswith("-") and token != "-":
            flag, _, inline = token.partition("=")
            opt = by_flag.get(flag)
            if opt is not None:
                seen.add(opt.dest)
                if opt.kind == "value" and not inline:
                    index += 2
                    continue
            index += 1
            continue
        if pos_index < len(positionals):
            opt = positionals[pos_index]
            if opt.choices and token.lower() not in {item.lower() for item in opt.choices}:
                index += 1
                continue
            seen.add(opt.dest)
            pos_index += 1
        index += 1
    return seen


def _emit(opt: Option, value: str) -> list[str]:
    if opt.kind == "bool":
        enabled = value.lower() in _TRUE
        if opt.store_false:
            enabled = not enabled
        if not enabled:
            return []
        flag = _long_flag(opt) or (opt.flags[0] if opt.flags else "")
        return [flag] if flag else []
    parts = shlex.split(value) if opt.repeatable or opt.kind == "tail" else [value]
    if opt.kind == "positional" or opt.kind == "tail":
        return parts
    flag = _long_flag(opt) or (opt.flags[0] if opt.flags else "")
    if not flag:
        return parts
    emitted: list[str] = []
    for part in parts:
        if part.startswith("-"):
            emitted.append(f"{flag}={part}")
        else:
            emitted.extend((flag, part))
    return emitted


def _long_flag(opt: Option) -> str:
    for flag in opt.flags:
        if flag.startswith("--"):
            return flag
    return ""


def _describe(opt: Option) -> str:
    text = opt.help or ""
    if opt.choices:
        text = f"{text} ({', '.join(opt.choices)})".strip()
    if opt.flags:
        text = f"{text}  {', '.join(opt.flags)}".strip()
    return text


def print_settings(name: str, settings: dict[str, str]) -> None:
    if not settings:
        ui.console.print(f"No options saved for [info]{escape(name)}[/info].")
        return
    for key in sorted(settings):
        ui.console.print(f"[info]{key}[/info] => {escape(settings[key])}")
