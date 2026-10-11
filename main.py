#!/usr/bin/env python3
"""SIEM Tool - Security Information & Event Management"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from siem.storage import Storage
from siem.parser import LogParser
from siem.collector import LogCollector
from siem.engine import RuleEngine
from siem.cli import run


def main():
    print("  [+] Initializing SIEM...")
    storage = Storage("siem.db")
    parser = LogParser()
    collector = LogCollector(storage, parser)
    engine = RuleEngine(storage)

    print("  [+] Storage ready (siem.db)")
    print("  [+] Parser loaded")
    print("  [+] Default rules loaded")
    print()

    try:
        run(storage, collector, parser, engine)
    except KeyboardInterrupt:
        print("\n  Shutting down...")
    finally:
        collector.stop()
        engine.stop()
        storage.close()
        print("  Bye.")


if __name__ == "__main__":
    main()
