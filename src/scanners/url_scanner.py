import ipaddress
import re
from urllib.parse import urlsplit


def scan_url(url):
    """Perform basic static security analysis of a URL."""

    findings = []
    score = 0
    url = url.strip()

    if not url:
        return {
            "url": url,
            "score": 0,
            "risk": "Invalid",
            "findings": ["No URL provided."]
        }

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Missing hostname.")

        # Reject whitespace within the URL.
        # Surrounding whitespace was already removed by strip().
        if any(character.isspace() for character in url):
            raise ValueError("URLs cannot contain unencoded whitespace.")

        # Validate that any supplied port is numeric and in range.
        _ = parsed.port

        # Detect URLs without HTTPS
        if parsed.scheme.lower() == "http":
            score += 20
            findings.append("URL does not use HTTPS.")

        # Detect IP-based URLs
        try:
            ipaddress.ip_address(hostname)
            score += 30
            findings.append("URL uses an IP address instead of a domain.")
        except ValueError:
            pass

        # Detect suspicious @ symbols
        if "@" in parsed.netloc:
            score += 30
            findings.append(
                "URL contains an @ symbol that may obscure its destination."
            )

        # Detect unusually long URLs
        if len(url) > 150:
            score += 15
            findings.append("URL is unusually long.")

        # Detect phishing-related keywords
        keywords = [
            "verify", "urgent", "password",
            "account", "login", "secure",
            "update", "confirm"
        ]

        matches = [
            word for word in keywords
            if re.search(r"\b" + re.escape(word) + r"\b",
                         url, re.IGNORECASE)
        ]

        if matches:
            score += min(len(matches) * 10, 30)
            findings.append(
                "Potential phishing keywords found: "
                + ", ".join(matches)
            )

        # Detect punycode hostnames
        if "xn--" in hostname.lower():
            score += 25
            findings.append(
                "Hostname contains punycode, which can be used in "
                "lookalike-domain attacks."
            )

        score = min(score, 100)

        if score >= 75:
            risk = "Critical"
        elif score >= 50:
            risk = "High"
        elif score >= 25:
            risk = "Medium"
        else:
            risk = "Low"

        if not findings:
            findings.append(
                "No suspicious characteristics detected by basic rules."
            )

        return {
            "url": url,
            "score": score,
            "risk": risk,
            "findings": findings
        }

    except (ValueError, TypeError) as error:
        return {
            "url": url,
            "score": 0,
            "risk": "Invalid",
            "findings": [str(error)]
        }
