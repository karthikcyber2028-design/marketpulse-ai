"""Plain-text and JSON report formatting for the checker."""

import json

RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
DIM = "\033[2m"


def _color(text, code, enabled):
    return "{}{}{}".format(code, text, RESET) if enabled else text


def email_report(email, breaches, color=True):
    """Human-readable report for a single email check."""
    if not breaches:
        return _color("[OK] {} - no known breaches".format(email), GREEN, color)
    lines = [
        _color(
            "[!] {} - found in {} breach(es)".format(email, len(breaches)),
            RED,
            color,
        )
    ]
    for breach in breaches:
        name = breach.get("Name", "unknown")
        title = breach.get("Title", name)
        added = breach.get("AddedDate", "").split("T")[0]
        if not added:
            added = "unknown"
        lines.append(
            "  {} - {} (added {})".format(
                _color(title, BOLD, color), _color(name, DIM, color), added
            )
        )
        exposed = breach.get("DataClasses")
        if exposed:
            lines.append("    exposed: {}".format(", ".join(exposed)))
    return "\n".join(lines)


def password_report(password, count, color=True):
    """Human-readable report for a password check."""
    if count == 0:
        return _color(
            "[OK] password not found in known breach data", GREEN, color
        )
    return _color(
        "[!] password pwned - seen {} times in breach data".format(count),
        RED,
        color,
    )


def to_json(obj):
    """Serialize a result dict to indented JSON."""
    return json.dumps(obj, indent=2, ensure_ascii=False)
