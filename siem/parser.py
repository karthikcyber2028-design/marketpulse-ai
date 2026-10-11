import re
import json
from datetime import datetime


class LogParser:
    SYSLOG_PATTERN = re.compile(
        r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.*)"
    )

    ISO_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    )

    COMMON_LOG_PATTERN = re.compile(
        r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:,\d+)?)\s+"
        r"\[?(?P<severity>DEBUG|INFO|WARNING|ERROR|CRITICAL|WARN|ERR|CRIT)\]?\s+"
        r"(?P<message>.*)"
    )

    SEVERITY_MAP = {
        "DEBUG": "debug", "INFO": "info", "WARNING": "warning",
        "WARN": "warning", "ERROR": "error", "ERR": "error",
        "CRITICAL": "critical", "CRIT": "critical", "ALERT": "critical",
        "NOTICE": "notice",
    }

    def parse(self, raw, source=None):
        raw_stripped = raw.strip()
        if not raw_stripped:
            return None

        parsed = self._try_json(raw_stripped)
        if parsed:
            return self._normalize(parsed, raw_stripped, source)

        parsed = self._try_syslog(raw_stripped)
        if parsed:
            return self._normalize(parsed, raw_stripped, source)

        parsed = self._try_common_log(raw_stripped)
        if parsed:
            return self._normalize(parsed, raw_stripped, source)

        return self._normalize({"message": raw_stripped}, raw_stripped, source)

    def _try_json(self, raw):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return {"_format": "json", **parsed}
        except (json.JSONDecodeError, ValueError):
            return None
        return None

    def _try_syslog(self, raw):
        m = self.SYSLOG_PATTERN.match(raw)
        if m:
            d = m.groupdict()
            d["_format"] = "syslog"
            return d
        return None

    def _try_common_log(self, raw):
        m = self.COMMON_LOG_PATTERN.match(raw)
        if m:
            d = m.groupdict()
            d["_format"] = "common_log"
            return d
        return None

    def _normalize(self, parsed, raw, source):
        timestamp = self._extract_timestamp(parsed)
        host = parsed.get("host", parsed.get("hostname", parsed.get("host_name", "")))
        log_type = parsed.get("_format", parsed.get("type", parsed.get("log_type", "unknown")))
        severity = self._extract_severity(parsed)
        return {
            "timestamp": timestamp,
            "host": host or "",
            "log_type": log_type,
            "severity": severity,
            "raw": raw,
            "parsed": {k: v for k, v in parsed.items() if not k.startswith("_")},
        }

    def _extract_timestamp(self, parsed):
        for key in ("timestamp", "time", "@timestamp", "date", "datetime", "ts"):
            val = parsed.get(key)
            if val:
                return str(val)
        return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    def _extract_severity(self, parsed):
        for key in ("severity", "level", "lvl", "priority", "event_type"):
            val = parsed.get(key)
            if val:
                val_upper = val.upper()
                if val_upper in self.SEVERITY_MAP:
                    return self.SEVERITY_MAP[val_upper]
                return val.lower()
        return "info"
