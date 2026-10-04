"""WebHawk toolkit shell.

The scanner still lives in ``webhawk.py``. This package routes commands
around that scanner and opens the interactive console. A target or a scan
flag never comes through here as a new subcommand: those arguments keep
running a scan.
"""

VERSION = "2.7.0"

__all__ = ["VERSION"]
