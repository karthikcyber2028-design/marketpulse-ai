"""Have I Been Pwned (HIBP) API client helpers (standard library only)."""

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request

BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
PASSWORD_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
USER_AGENT = "digital-footprint-checker/1.0"


class HIBPError(Exception):
    """Base error for HIBP API calls."""


class AuthError(HIBPError):
    """The request was rejected with 401 - an API key is required."""


class RateLimitError(HIBPError):
    """The rate limit was exceeded (HTTP 429)."""


def _api_request(url, api_key=None, timeout=15):
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if api_key:
        headers["hibp-api-key"] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body
    except urllib.error.URLError as exc:
        raise HIBPError("network error: {}".format(exc.reason)) from exc


def check_email_breaches(email, api_key=None, timeout=15):
    """Return breach records for an email via the HIBP v3 API.

    Requires ``api_key`` (a HIBP API key, usually set via the HIBP_API_KEY
    environment variable). Returns a list of breach dicts, empty when the
    account appears in no known breaches.
    """
    url = BREACH_URL.format(urllib.parse.quote(email.strip().lower()))
    status, body = _api_request(url, api_key, timeout)
    if status == 200:
        return json.loads(body)
    if status == 404:
        return []
    if status == 401:
        raise AuthError("HIBP requires an API key (set --api-key or HIBP_API_KEY)")
    if status == 403:
        raise HIBPError("forbidden: the API key may be invalid or expired")
    if status == 429:
        raise RateLimitError(
            "rate limit exceeded; increase --delay or use an API key"
        )
    raise HIBPError("HIBP returned HTTP {}".format(status))


def _sha1(text):
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()


def check_password_pwned(password, timeout=15):
    """Return how many times ``password`` appears in known breaches.

    Uses the HIBP k-anonymity range API: only the first five characters of
    the SHA-1 hash leave the machine, so the plaintext password is never
    sent over the wire. Returns 0 when the password has not been seen.
    """
    digest = _sha1(password)
    prefix, suffix = digest[:5], digest[5:]
    status, body = _api_request(
        PASSWORD_RANGE_URL.format(prefix), None, timeout
    )
    if status != 200:
        raise HIBPError("password range endpoint returned HTTP {}".format(status))
    for line in body.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix.strip().upper() == suffix:
            return int(count.strip())
    return 0
