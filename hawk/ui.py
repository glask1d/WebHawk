"""Console for framework commands. The scanner keeps its own console.

Framework help and reports go to stdout so `webhawk --help` and
`webhawk modules` can be piped. Scan progress stays on the scanner console.
"""

import sys

from rich.console import Console
from rich.theme import Theme

THEME = Theme(
    {
        "ok": "bold green",
        "warn": "bold yellow",
        "err": "bold red",
        "info": "bold cyan",
        "muted": "dim",
        "brand": "bold bright_magenta",
    }
)

console = Console(theme=THEME, highlight=False, file=sys.stdout)
