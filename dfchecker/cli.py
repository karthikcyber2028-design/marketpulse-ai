"""Command-line interface for the digital footprint & exposure checker."""

import argparse
import os
import sys
import time

from . import hibp
from . import report


def _color_enabled(args):
    if args.no_color:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _api_key(provided):
    return provided or os.environ.get("HIBP_API_KEY", "").strip() or None


def _cmd_email(args):
    api_key = _api_key(args.api_key)
    if not api_key:
        print(
            "error: checking emails requires a HIBP API key.\n"
            "  Provide one with --api-key KEY or the HIBP_API_KEY environment variable.\n"
            "  (Keys are free: https://haveibeenpwned.com/API/Key)",
            file=sys.stderr,
        )
        return 2

    color = _color_enabled(args)
    results = {}
    found = failed = 0
    for index, email in enumerate(args.emails):
        if index > 0:
            time.sleep(args.delay)
        try:
            breaches = hibp.check_email_breaches(email, api_key, args.timeout)
        except hibp.HIBPError as exc:
            print("[ERR] {}: {}".format(email, exc), file=sys.stderr)
            results[email] = {"error": str(exc)}
            failed += 1
            continue
        results[email] = {"breaches": breaches, "count": len(breaches)}
        if not args.json:
            print(report.email_report(email, breaches, color))
        if breaches:
            found += 1

    if args.json:
        print(report.to_json(results))
        return 1 if found else (2 if failed else 0)

    print()
    print(
        "Summary: {} of {} email(s) appear in known breaches.".format(
            found, len(args.emails)
        )
    )
    return 1 if found else (2 if failed else 0)


def _cmd_password(args):
    color = _color_enabled(args)
    count = hibp.check_password_pwned(args.password, args.timeout)
    if args.json:
        print(report.to_json({"password": args.password, "pwned_count": count}))
    else:
        print(report.password_report(args.password, count, color))
    return 1 if count else 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="dfchecker",
        description=(
            "Digital Footprint & Exposure Checker - check emails and "
            "passwords against known breach data (Have I Been Pwned)."
        ),
    )
    parser.add_argument(
        "--no-color", action="store_true", help="disable ANSI colors"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=15,
        help="HTTP timeout in seconds (default 15)",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    email_parser = sub.add_parser(
        "email", help="check email addresses against known breaches"
    )
    email_parser.add_argument(
        "emails", nargs="+", help="one or more email addresses"
    )
    email_parser.add_argument(
        "--api-key",
        default=None,
        help="HIBP API key (or set the HIBP_API_KEY environment variable)",
    )
    email_parser.add_argument(
        "--delay",
        type=float,
        default=1.5,
        help="seconds between API calls (default 1.5)",
    )
    email_parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON only"
    )
    email_parser.set_defaults(func=_cmd_email)

    pw_parser = sub.add_parser(
        "password",
        help="check whether a password appears in known breaches",
    )
    pw_parser.add_argument(
        "password", help="the password to check (never transmitted as plaintext)"
    )
    pw_parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON only"
    )
    pw_parser.set_defaults(func=_cmd_password)

    return parser


def run(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except hibp.HIBPError as exc:
        print("[ERR] {}".format(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
