#!/usr/bin/env python3
"""Digital Footprint & Exposure Checker - command line entry point."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dfchecker.cli import run


if __name__ == "__main__":
    sys.exit(run())
