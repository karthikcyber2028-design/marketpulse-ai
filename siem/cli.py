import os
import sys
import time
from datetime import datetime, timedelta


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def print_header():
    print("=" * 60)
    print("  SIEM Tool - Security Information & Event Management")
    print("=" * 60)


def print_menu():
    print("\n  ┌─── MAIN MENU ──────────────────────────────┐")
    print("  │  1.  Live log tail                          │")
    print("  │  2.  Search events                          │")
    print("  │  3.  Statistics                             │")
    print("  │  4.  View alerts                            │")
    print("  │  5.  Manage rules                           │")
    print("  │  6.  Add log source                         │")
    print("  │  7.  Ingest manual log line                 │")
    print("  │  8.  Generate test events                   │")
    print("  │  9.  Export events (JSON)                   │")
    print("  │  0.  Exit                                   │")
    print("  └────────────────────────────────────────────┘")


def live_tail(storage, poll_interval=2):
    clear()
    print_header()
    print("\n  [*] Live tail (updates every {}s). Press Ctrl+C to stop.\n".format(poll_interval))
    try:
        last_id = 0
        while True:
            events = storage.search_events(limit=20)
            new_events = [e for e in events if e["id"] > last_id]
            for ev in reversed(new_events):
                ts = ev.get("timestamp", "")
                sev = ev.get("severity", "").upper()
                src = ev.get("source", "")
                raw = ev.get("raw", "")[:120]
                print(f"  [{sev:>8}] {ts} | {src:<20} | {raw}")
            if new_events:
                last_id = new_events[0]["id"]
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        pass


def search_events(storage):
    clear()
    print_header()
    print("\n  ── Search Events ──")
    query = input("  Search text (Enter for all): ").strip() or None
    source = input("  Source filter (Enter to skip): ").strip() or None
    severity = input("  Severity filter (debug/info/warning/error/critical) (Enter to skip): ").strip() or None
    log_type = input("  Log type filter (Enter to skip): ").strip() or None
    limit_str = input("  Results limit (default 50): ").strip()
    limit = int(limit_str) if limit_str.isdigit() else 50

    print(f"\n  Searching...\n")
    results = storage.search_events(query=query, source=source, severity=severity, log_type=log_type, limit=limit)
    print(f"  Found {len(results)} event(s):\n")
    for ev in results:
        ts = ev.get("timestamp", "")
        sev = ev.get("severity", "").upper()
        src = ev.get("source", "")
        raw = ev.get("raw", "")[:150]
        print(f"  [{sev:>8}] {ts} | {src:<20} | {raw}")
    input("\n  Press Enter to continue...")


def show_stats(storage):
    clear()
    print_header()
    print("\n  ── Statistics ──\n")
    stats = storage.stats()
    print(f"  Total events ingested: {stats['total']}")
    print()
    print("  Events by Source:")
    for src, cnt in stats["by_source"][:10]:
        print(f"    {src:<30} {cnt}")
    print()
    print("  Events by Severity:")
    for sev, cnt in stats["by_severity"]:
        print(f"    {sev:<30} {cnt}")
    print()
    print("  Events by Type:")
    for ltype, cnt in stats["by_type"][:10]:
        print(f"    {ltype:<30} {cnt}")
    input("\n  Press Enter to continue...")


def view_alerts(storage):
    clear()
    print_header()
    print("\n  ── Recent Alerts ──\n")
    alerts = storage.get_alerts(limit=50)
    if not alerts:
        print("  No alerts generated yet.")
    else:
        for a in alerts:
            print(f"  [{a['severity'].upper():>8}] {a['created_at']} | {a['rule_name']:<25} | {a['message'][:100]}")
    input("\n  Press Enter to continue...")


def manage_rules(storage):
    clear()
    print_header()
    print("\n  ── Manage Rules ──\n")
    rules = storage.get_rules(enabled_only=False)
    if not rules:
        print("  No rules defined.")
    else:
        print(f"  {'ID':<4} {'Name':<30} {'Severity':<10} {'Type':<12} {'Enabled':<8} {'Pattern'}")
        print("  " + "-" * 90)
        for r in rules:
            enabled = "Yes" if r["enabled"] else "No"
            print(f"  {r['id']:<4} {r['name']:<30} {r['severity']:<10} {r['condition_type']:<12} {enabled:<8} {r['pattern']}")
    print()
    print("  Options:")
    print("  [a] Add new rule")
    print("  [Enter] Back to menu")
    choice = input("  > ").strip().lower()
    if choice == "a":
        add_rule(storage)


def add_rule(storage):
    print("\n  ── Add Rule ──")
    name = input("  Name: ").strip()
    desc = input("  Description: ").strip()
    severity = input("  Severity (low/medium/high/critical) [medium]: ").strip() or "medium"
    ctype = input("  Condition type (pattern/threshold) [pattern]: ").strip() or "pattern"
    pattern = input("  Regex pattern: ").strip()
    threshold = 1
    window = 0
    if ctype == "threshold":
        t = input("  Threshold count [5]: ").strip()
        threshold = int(t) if t.isdigit() else 5
        w = input("  Window (seconds) [300]: ").strip()
        window = int(w) if w.isdigit() else 300
    if storage.insert_rule(name, desc, severity, ctype, pattern, threshold, window):
        print("  [+] Rule added successfully.")
    else:
        print("  [!] Rule with that name already exists.")
    input("  Press Enter to continue...")


def add_source(collector):
    clear()
    print_header()
    print("\n  ── Add Log Source ──\n")
    path = input("  Path to log file or directory: ").strip()
    if not path:
        return
    name = input("  Source name (Enter for auto): ").strip() or None
    if os.path.isfile(path):
        collector.watch_file(path, name)
    elif os.path.isdir(path):
        collector.add_directory(path)
    else:
        print(f"  [!] Invalid path: {path}")
    print()
    input("  Press Enter to continue...")


def ingest_manual(storage, parser):
    clear()
    print_header()
    print("\n  ── Manual Log Ingestion ──")
    print("  Enter log lines (empty line to finish):\n")
    lines = []
    while True:
        line = input("  > ")
        if not line:
            break
        lines.append(line)
    for line in lines:
        result = parser.parse(line, source="manual")
        if result:
            storage.insert_event(**result)
            print(f"  [+] Ingested: {line[:80]}")
        else:
            print(f"  [-] Skipped: {line[:80]}")
    input("\n  Press Enter to continue...")


def generate_test_events(storage, parser):
    clear()
    print_header()
    print("\n  ── Generate Test Events ──\n")
    count_str = input("  Number of events to generate [20]: ").strip()
    count = int(count_str) if count_str.isdigit() else 20

    import random
    severities = ["debug", "info", "info", "info", "warning", "error", "critical"]
    messages = [
        "User login successful from 192.168.1.{}",
        "Failed login attempt for user admin from 10.0.0.{}",
        "Connection refused on port 22 from {}",
        "File access denied: /etc/shadow",
        "SYN scan detected from 172.16.0.{}",
        "Firewall rule triggered: blocked port 443",
        "DNS query for malware.example.com blocked",
        "CPU usage at 95% on server {}",
        "Disk space warning on /var/log: 5% remaining",
        "CRITICAL - Buffer overflow attempt detected from {}",
    ]
    sources = ["auth.log", "syslog", "nginx/access.log", "firewall.log", "ids/alert.log"]

    now = datetime.utcnow()
    for i in range(count):
        ts = (now - timedelta(seconds=random.randint(0, 3600))).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg = random.choice(messages).format(random.randint(1, 255))
        sev = random.choice(severities)
        src = random.choice(sources)
        line = f"{ts} [{sev.upper()}] {msg}"
        result = parser.parse(line, source=src)
        if result:
            storage.insert_event(**result)
    print(f"  [+] Generated {count} test events.")
    input("\n  Press Enter to continue...")


def export_events(storage):
    clear()
    print_header()
    print("\n  ── Export Events ──\n")
    limit_str = input("  Number of events to export [1000]: ").strip()
    limit = int(limit_str) if limit_str.isdigit() else 1000
    fname = input("  Output filename [events_export.json]: ").strip() or "events_export.json"

    events = storage.search_events(limit=limit)
    import json
    with open(fname, "w") as f:
        json.dump(events, f, indent=2, default=str)
    print(f"  [+] Exported {len(events)} events to {fname}")
    input("\n  Press Enter to continue...")


def run(storage, collector, parser, engine):
    collector.start()
    engine.start()

    while True:
        clear()
        print_header()
        print_menu()
        choice = input("\n  Enter choice: ").strip()

        if choice == "1":
            live_tail(storage)
        elif choice == "2":
            search_events(storage)
        elif choice == "3":
            show_stats(storage)
        elif choice == "4":
            view_alerts(storage)
        elif choice == "5":
            manage_rules(storage)
        elif choice == "6":
            add_source(collector)
        elif choice == "7":
            ingest_manual(storage, parser)
        elif choice == "8":
            generate_test_events(storage, parser)
        elif choice == "9":
            export_events(storage)
        elif choice == "0":
            print("\n  Shutting down...")
            collector.stop()
            engine.stop()
            storage.close()
            print("  Done.")
            break
        else:
            print("\n  [!] Invalid choice.")
            time.sleep(1)
