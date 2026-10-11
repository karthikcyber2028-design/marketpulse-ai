import re
import threading
import time
from datetime import datetime, timedelta


class RuleEngine:
    def __init__(self, storage):
        self.storage = storage
        self.running = False
        self._thread = None
        self._load_default_rules()

    def _load_default_rules(self):
        defaults = [
            {
                "name": "multiple_failed_logins",
                "description": "Multiple failed login attempts detected",
                "severity": "high",
                "condition_type": "threshold",
                "pattern": "failed (login|password|authentication)",
                "threshold": 5,
                "window_seconds": 300,
            },
            {
                "name": "error_spike",
                "description": "High volume of error events",
                "severity": "medium",
                "condition_type": "threshold",
                "pattern": "error",
                "threshold": 50,
                "window_seconds": 60,
            },
            {
                "name": "critical_event",
                "description": "Critical severity event detected",
                "severity": "critical",
                "condition_type": "pattern",
                "pattern": "CRITICAL|critical|CRIT",
                "threshold": 1,
                "window_seconds": 0,
            },
            {
                "name": "port_scan",
                "description": "Possible port scanning activity",
                "severity": "high",
                "condition_type": "threshold",
                "pattern": "SYN|port scan|connection refused",
                "threshold": 20,
                "window_seconds": 120,
            },
            {
                "name": "malware_signature",
                "description": "Known malware indicator detected",
                "severity": "critical",
                "condition_type": "pattern",
                "pattern": "malware|trojan|ransomware|C2|beacon",
                "threshold": 1,
                "window_seconds": 0,
            },
        ]
        for rule in defaults:
            self.storage.insert_rule(**rule)

    def start(self, check_interval=10):
        self.running = True
        self._thread = threading.Thread(target=self._loop, args=(check_interval,), daemon=True)
        self._thread.start()
        print(f"  [*] Rule engine started (check interval: {check_interval}s)")

    def stop(self):
        self.running = False

    def _loop(self, interval):
        while self.running:
            try:
                self._evaluate_rules()
            except Exception as e:
                print(f"  [!] Rule engine error: {e}")
            time.sleep(interval)

    def _evaluate_rules(self):
        rules = self.storage.get_rules(enabled_only=True)
        for rule in rules:
            if rule["condition_type"] == "pattern":
                self._check_pattern_rule(rule)
            elif rule["condition_type"] == "threshold":
                self._check_threshold_rule(rule)

    def _check_pattern_rule(self, rule):
        pattern = rule["pattern"]
        try:
            recent = self.storage.search_events(limit=1000)
            for event in recent:
                raw = event.get("raw", "") or ""
                if re.search(pattern, raw, re.IGNORECASE):
                    self._fire_alert(rule, [event])
                    break
        except re.error:
            pass

    def _check_threshold_rule(self, rule):
        try:
            window_start = (datetime.utcnow() - timedelta(seconds=rule["window_seconds"])).strftime("%Y-%m-%dT%H:%M:%SZ")
            if rule["window_seconds"] <= 0:
                return
            events = self.storage.search_events(
                start_time=window_start, limit=10000
            )
            pattern = rule["pattern"]
            matches = [e for e in events if re.search(pattern, e.get("raw", "") or "", re.IGNORECASE)]
            if len(matches) >= rule["threshold"]:
                self._fire_alert(rule, matches[:10])
        except re.error:
            pass

    def _fire_alert(self, rule, matched_events):
        count = len(matched_events)
        msg = f"Rule '{rule['name']}': {rule['description']} ({count} event(s))"
        self.storage.insert_alert(
            rule_id=rule["id"],
            rule_name=rule["name"],
            severity=rule["severity"],
            message=msg,
            matched_events=[e.get("id") for e in matched_events if e.get("id")],
        )
        print(f"  [ALERT] [{rule['severity'].upper()}] {msg}")
