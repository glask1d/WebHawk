#!/usr/bin/env python3
"""Compatibility wrapper. Always runs a WebHawk scan, never the toolkit shell."""
from webhawk import scan_main

if __name__ == "__main__":
    raise SystemExit(scan_main())
