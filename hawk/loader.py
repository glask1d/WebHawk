"""Run the scanner or a reference tool.

The one-shot commands and the interactive console both call `run_named`.
A Python tool is imported from its clone and `main` is called in-process.
Tools that read `sys.argv` see `webhawk <module>` as the program name.
A shell program is run with bash, so the clone does not need to be executable.
`SystemExit` from a tool becomes a return code so the console can keep running.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import inspect
import subprocess
import sys
import traceback
from collections.abc import Callable
from pathlib import Path

from rich.markup import escape

from hawk import ui
from hawk.catalog import locate_script, reference_canonical, tool_by_command

ScanMain = Callable[..., int]


def exit_code(exc: SystemExit) -> int:
    code = exc.code
    if code is None or code == 0:
        return 0
    if isinstance(code, int):
        return code
    return 1


def run_named(name: str, argv: list[str], *, tool_file: Path, scan_main: ScanMain) -> int:
    """Run `scan` or a reference module. `name` may be an alias."""
    if name == "scan":
        try:
            return scan_main(list(argv), prog="webhawk scan")
        except SystemExit as exc:
            return exit_code(exc)

    canonical = reference_canonical(name)
    if canonical:
        from hawk.modules import MODULES

        if canonical in MODULES:
            return _run_builtin(canonical, argv)
    tool = tool_by_command(canonical) if canonical else None
    if tool is None or canonical is None:
        ui.console.print(f"[err]Unknown module[/err] {escape(name)}")
        return 2
    script = locate_script(tool, tool_file)
    if script is None:
        return _missing_clone(name, canonical, argv, tool.folder, tool.script)
    if not looks_like_python(script):
        return _run_program(script, argv, canonical)
    try:
        module = _import_script(script)
    except ModuleNotFoundError as exc:
        missing = exc.name or str(exc)
        ui.console.print(f"[err]{escape(canonical)}[/err] could not start.")
        ui.console.print(f"Missing package: {missing}", markup=False)
        ui.console.print("Install that tool's requirements, then try again.")
        return 2
    except Exception:
        ui.console.print(f"[err]{escape(canonical)}[/err] could not be loaded from")
        ui.console.print(f"  {script}", markup=False, crop=False, no_wrap=True, overflow="ignore")
        traceback.print_exc()
        return 1
    try:
        return _call_main(module, argv, canonical, script)
    except KeyboardInterrupt:
        raise
    except Exception:
        ui.console.print(f"[err]{escape(canonical)}[/err] failed.")
        traceback.print_exc()
        return 1


def _run_builtin(canonical: str, argv: list[str]) -> int:
    from hawk.modules import load_builtin

    try:
        module = load_builtin(canonical)
    except Exception:
        ui.console.print(f"[err]{escape(canonical)}[/err] could not be loaded.")
        traceback.print_exc()
        return 1
    script = Path(getattr(module, "__file__", canonical))
    try:
        return _call_main(module, argv, canonical, script)
    except KeyboardInterrupt:
        raise
    except Exception:
        ui.console.print(f"[err]{escape(canonical)}[/err] failed.")
        traceback.print_exc()
        return 1


def _missing_clone(token: str, canonical: str, argv: list[str], folder: str, script: str) -> int:
    shown = token if token == canonical else f"{token} ({canonical})"
    ui.console.print(f"[warn]{escape(shown)}[/warn] is a WebHawk module, and its program was not found.")
    ui.console.print("Nothing was run.")
    ui.console.print(f"\nLooked for {folder}/{script} under WEBHAWK_ADDONS, ./addons, and ../addons.")
    if argv:
        ui.console.print("Arguments not forwarded: " + " ".join(argv), markup=False)
    ui.console.print(f"\nTo scan a host named {token}:\n  webhawk scan {token}")
    return 2


def looks_like_python(script: Path) -> bool:
    if script.suffix.lower() == ".py":
        return True
    try:
        with script.open("r", encoding="utf-8", errors="replace") as handle:
            first = handle.readline(200).lower()
    except OSError:
        return False
    return "python" in first


def _run_program(script: Path, argv: list[str], canonical: str) -> int:
    """Run a shell program. bash is used so the clone does not need +x."""
    try:
        with script.open("r", encoding="utf-8", errors="replace") as handle:
            first = handle.readline(200).lower()
    except OSError as exc:
        ui.console.print(f"[err]{escape(canonical)}[/err] could not be read: {exc}")
        return 1
    if "python" in first:
        command = [sys.executable, str(script), *argv]
    else:
        command = ["bash", str(script), *argv]
    try:
        completed = subprocess.run(command, check=False)
    except KeyboardInterrupt:
        raise
    except OSError as exc:
        ui.console.print(f"[err]{escape(canonical)}[/err] could not start: {exc}")
        return 1
    return int(completed.returncode or 0)


def import_script(script: Path):
    """Import a tool module. Used by the option reader and by `run`."""
    return _import_script(script)


def _module_key(script: Path) -> str:
    digest = hashlib.sha1(str(script.resolve()).encode()).hexdigest()[:12]
    stem = script.stem.replace("-", "_")
    return f"webhawk_tools.{stem}_{digest}"


def _import_script(script: Path):
    script = script.resolve()
    key = _module_key(script)
    loaded = sys.modules.get(key)
    if loaded is not None and getattr(loaded, "__file__", None) == str(script):
        return loaded
    spec = importlib.util.spec_from_file_location(key, script)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    parent = str(script.parent.resolve())
    inserted = parent not in sys.path
    if inserted:
        sys.path.insert(0, parent)
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(key, None)
        raise
    finally:
        if inserted:
            try:
                sys.path.remove(parent)
            except ValueError:
                pass
    return module


def _accepts_argv(main: Callable) -> bool:
    try:
        signature = inspect.signature(main)
    except (TypeError, ValueError):
        return False
    for param in signature.parameters.values():
        if param.kind in (
            param.POSITIONAL_ONLY,
            param.POSITIONAL_OR_KEYWORD,
            param.VAR_POSITIONAL,
        ):
            return True
    return False


def _call_main(module, argv: list[str], canonical: str, script: Path) -> int:
    main = getattr(module, "main", None)
    if not callable(main):
        ui.console.print(f"[err]{escape(canonical)}[/err] has no main().")
        ui.console.print(f"  {script}", markup=False, crop=False, no_wrap=True, overflow="ignore")
        return 2
    old_argv = sys.argv
    parent = str(script.parent.resolve())
    inserted = parent not in sys.path
    if inserted:
        sys.path.insert(0, parent)
    sys.argv = [f"webhawk {canonical}", *argv]
    try:
        if _accepts_argv(main):
            result = main(list(argv))
        else:
            result = main()
        if inspect.iscoroutine(result):
            result = asyncio.run(result)
    except SystemExit as exc:
        return exit_code(exc)
    finally:
        sys.argv = old_argv
        if inserted:
            try:
                sys.path.remove(parent)
            except ValueError:
                pass
    if result is None or result is True:
        return 0
    if isinstance(result, int) and not isinstance(result, bool):
        return result
    return 0
