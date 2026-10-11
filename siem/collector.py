import os
import time
import threading
from pathlib import Path
from datetime import datetime


class LogCollector:
    def __init__(self, storage, parser):
        self.storage = storage
        self.parser = parser
        self.sources = {}
        self.running = False
        self._threads = []

    def watch_file(self, path, source_name=None):
        path = Path(path)
        if not path.exists():
            print(f"  [!] Path does not exist: {path}")
            return False
        source_name = source_name or path.name
        if path.is_dir():
            for f in sorted(path.glob("*")):
                if f.is_file():
                    self.watch_file(f, f"{source_name}/{f.name}")
            return True

        stat = path.stat()
        self.sources[str(path)] = {
            "name": source_name,
            "path": str(path),
            "size": stat.st_size,
            "inode": stat.st_ino if hasattr(stat, "st_ino") else None,
            "mtime": stat.st_mtime,
        }
        print(f"  [+] Watching: {path}  (source: {source_name})")
        return True

    def start(self, poll_interval=1.0):
        self.running = True
        t = threading.Thread(target=self._poll_loop, args=(poll_interval,), daemon=True)
        self._threads.append(t)
        t.start()
        print(f"  [*] Collector started (poll interval: {poll_interval}s)")
        return t

    def stop(self):
        self.running = False

    def _poll_loop(self, interval):
        while self.running:
            for path_str, info in list(self.sources.items()):
                try:
                    self._check_file(path_str, info)
                except Exception as e:
                    print(f"  [!] Error reading {path_str}: {e}")
            time.sleep(interval)

    def _check_file(self, path_str, info):
        try:
            stat = os.stat(path_str)
        except FileNotFoundError:
            return

        current_size = stat.st_size
        if current_size < info["size"]:
            info["size"] = 0
        if current_size == info["size"]:
            return

        with open(path_str, "r", encoding="utf-8", errors="replace") as f:
            f.seek(info["size"])
            lines = f.readlines()

        info["size"] = current_size
        info["mtime"] = stat.st_mtime

        for line in lines:
            line = line.rstrip("\n\r")
            if not line:
                continue
            result = self.parser.parse(line, source=info["name"])
            if result:
                self.storage.insert_event(
                    timestamp=result["timestamp"],
                    source=info["name"],
                    host=result["host"],
                    log_type=result["log_type"],
                    severity=result["severity"],
                    raw=result["raw"],
                    parsed=result["parsed"],
                )

    def ingest_line(self, line, source="manual"):
        result = self.parser.parse(line, source=source)
        if result:
            self.storage.insert_event(
                timestamp=result["timestamp"],
                source=source,
                host=result["host"],
                log_type=result["log_type"],
                severity=result["severity"],
                raw=result["raw"],
                parsed=result["parsed"],
            )
            return True
        return False

    def add_directory(self, path, pattern="*"):
        path = Path(path)
        if not path.is_dir():
            print(f"  [!] Not a directory: {path}")
            return
        for f in sorted(path.glob(pattern)):
            if f.is_file():
                self.watch_file(f)
