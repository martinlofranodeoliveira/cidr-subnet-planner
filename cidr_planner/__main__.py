"""Module execution entry point for `python3 -m cidr_planner`."""

import sys

from cidr_planner.cli import main

if __name__ == "__main__":
    sys.exit(main())
