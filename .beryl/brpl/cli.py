"""Compatibility entry point for the active BRPL v2 command line."""

from .v2.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
