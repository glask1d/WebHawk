"""Built-in WebHawk modules. These ship with the console, not as addon clones."""

from __future__ import annotations

import importlib

MODULES: dict[str, str] = {
    "scope": "Manage in-scope hosts and the shared URL list.",
    "robots": "Turn robots.txt and sitemaps into URLs for pulse.",
    "repeater": "Edit a captured HTTP request, then send it again.",
}


def load_builtin(name: str):
    if name not in MODULES:
        raise KeyError(name)
    return importlib.import_module(f"hawk.modules.{name}")
