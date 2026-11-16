"""Sn00py Bl0ck3r: static URL triage (never connects to a submitted URL)."""

import ipaddress
import re
from urllib.parse import urlsplit

MAX_URL_LENGTH = 8192
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "cutt.ly", "tiny.cc", "rebrand.ly", "shorturl.at",
}
KEYWORDS = (
    "verify", "urgent", "password", "account", "login", "secure",
    "update", "confirm", "signin", "reset", "wallet", "payment",
)


def risk_label(score):
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _invalid(reason):
    return {"score": 0, "risk": "Invalid", "findings": [reason], "url": ""}


def scan_url(url):
    """Analyze an HTTP(S) URL without DNS, HTTP requests, or browsing.

    Scores describe indicators of suspicion, NOT a confirmed threat verdict.
    Findings deliberately omit full URLs, query parameters, and credentials.
    """
    if not isinstance(url, str) or not url.strip():
        return _invalid("No URL provided.")
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        return _invalid("URL exceeds the 8192-character input limit.")
    if any(c.isspace() or ord(c) < 32 for c in url):
        return _invalid("URL contains whitespace or control characters.")

    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("URL is missing a hostname.")
        if len(hostname) > 253:
            raise ValueError("Hostname exceeds the maximum supported length.")
        _ = parsed.port  # Validate numeric port/range.
        port = parsed.port
        if not parsed.netloc:
            raise ValueError("URL is missing a network location.")
        try:
            ascii_host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ValueError("Hostname is not a valid IDN hostname.")
    except ValueError as exc:
        # Parser errors are controlled here, never include raw submitted URL.
        return _invalid(str(exc))

    score = 0
    findings = []

    if parsed.scheme.lower() == "http":
        score += 20
        findings.append("URL uses HTTP rather than encrypted HTTPS.")

    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(ascii_host.strip("[]"))
        is_ip = True
        score += 30
        findings.append("URL uses a numeric IP address instead of a domain.")
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            findings.append("The IP address belongs to a non-public address range.")
    except ValueError:
        pass

    if "@" in parsed.netloc:
        score += 30
        findings.append("URL contains userinfo or an @ symbol that may hide its destination.")

    if len(url) > 150:
        score += 15
        findings.append("URL is unusually long.")

    # Only report keywords from a fixed allowlist; never expose arbitrary query text.
    path_query = (parsed.path + "?" + parsed.query).lower()
    keywords_found = [word for word in KEYWORDS if re.search(r"(?<![a-z])" + word + r"(?![a-z])", path_query)]
    if keywords_found:
        score += min(len(keywords_found) * 10, 30)
        findings.append("Phishing-related words appear in the URL path or query: " + ", ".join(keywords_found[:4]) + ".")

    if any(label.startswith("xn--") for label in ascii_host.split(".")):
        score += 25
        findings.append("Hostname uses punycode, which can conceal lookalike domains.")

    if not is_ip:
        if ascii_host in SHORTENERS or any(ascii_host.endswith("." + name) for name in SHORTENERS):
            score += 15
            findings.append("URL uses a link-shortening domain, concealing its final destination.")
        if len(ascii_host.split(".")) >= 5:
            score += 10
            findings.append("Hostname has an unusually large number of subdomains.")

    if port is not None and port not in (80, 443):
        score += 10
        findings.append("URL uses a nonstandard network port.")

    score = min(score, 100)
    if not findings:
        findings.append("No indicators matched the current static URL checks; this does not prove safety.")
    return {"url": url, "score": score, "risk": risk_label(score), "findings": findings}
