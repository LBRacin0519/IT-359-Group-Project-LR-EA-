"""Local-only email phishing heuristics; no messages or URLs are fetched.

Supports pasted plain email text and pasted RFC-style headers separated from
body by a blank line. Does not verify a message's authenticity or parse MIME.
"""

import re
from email.utils import parseaddr
from urllib.parse import urlsplit

from scanners.url_scanner import scan_url

MAX_EMAIL_CHARS = 100_000
MAX_URLS = 10
_URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
_HEADER_RE = re.compile(r'^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$')
_HEADER_STARTS = ('from:', 'to:', 'reply-to:', 'return-path:', 'subject:',
                  'date:', 'authentication-results:', 'received:')


def _risk_label(score):
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _parse_pasted_headers(content):
    """Read a conventional header block only when it is clearly delimited."""
    normalized = content.replace('\r\n', '\n').replace('\r', '\n')
    header_block, delimiter, body = normalized.partition('\n\n')
    if not delimiter or len(header_block) > 8192:
        return {}

    lines = header_block.split('\n')
    if not lines or not lines[0].lower().startswith(_HEADER_STARTS):
        return {}

    headers = {}
    last_key = None
    for line in lines:
        if line.startswith((' ', '\t')) and last_key:
            headers[last_key][-1] += ' ' + line.strip()
            continue
        match = _HEADER_RE.match(line)
        if not match:
            # Not a reliable header block; treat entire input as ordinary text.
            return {}
        last_key = match.group(1).lower()
        headers.setdefault(last_key, []).append(match.group(2).strip())
    return headers


def _address_domain(header_value):
    address = parseaddr(header_value)[1]
    if address.count('@') != 1:
        return None
    return address.rsplit('@', 1)[1].lower().rstrip('.')


def _domains_related(a, b):
    return a == b or a.endswith('.' + b) or b.endswith('.' + a)


def _extract_urls(content):
    """Deduplicate links while never opening them or downloading content."""
    urls = []
    seen = set()
    for match in _URL_RE.finditer(content):
        url = match.group(0).rstrip('.,;!?)>]')
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _safe_hostname(url):
    try:
        host = urlsplit(url).hostname or 'unknown host'
    except ValueError:
        host = 'unknown host'
    # Bound and sanitize any attacker-controlled hostname shown to the model.
    return re.sub(r'[^A-Za-z0-9.:-]', '', host)[:120] or 'unknown host'


def scan_email(content):
    """Return the existing score/risk/findings contract for Streamlit + Sushi AI."""
    if not isinstance(content, str) or not content.strip():
        return {"score": 0, "risk": "Invalid",
                "findings": ["No email content provided."]}
    if len(content) > MAX_EMAIL_CHARS:
        return {"score": 0, "risk": "Invalid",
                "findings": ["Email text exceeds the 100,000-character limit."]}

    content = content.strip()
    score = 0
    findings = []

    # Keep the original 5 rule groups and point values unchanged.
    rules = [
        (r'\b(urgent|immediately|act now|within 24 hours)\b', 15,
         'Urgency language may pressure the recipient to act quickly.'),
        (r'\b(verify your account|confirm your password|'
         r'enter your password|send your password)\b', 25,
         'The message requests account verification or password action.'),
        (r'\b(account suspended|account will be closed|'
         r'account will be locked)\b', 20,
         'The message threatens loss of account access.'),
        (r'\b(gift cards?|wire transfer|send bitcoin)\b', 20,
         'The message mentions payment methods often used in scams.'),
        (r'\b(you have won|claim your prize|lottery winner)\b', 20,
         'The message uses prize or lottery language.'),
    ]
    for pattern, points, explanation in rules:
        if re.search(pattern, content, flags=re.IGNORECASE):
            score += points
            findings.append(explanation)

    headers = _parse_pasted_headers(content)
    if headers:
        sender = _address_domain(headers.get('from', [''])[0])
        reply_to = _address_domain(headers.get('reply-to', [''])[0])
        if sender and reply_to and not _domains_related(sender, reply_to):
            score += 20
            findings.append(
                'From and Reply-To domains differ; verify the sender through a known channel.'
            )
        auth_values = ' '.join(headers.get('authentication-results', []))
        if re.search(r'\b(?:spf|dkim|dmarc)\s*=\s*(?:fail|hardfail|softfail)\b',
                     auth_values, flags=re.IGNORECASE):
            score += 25
            findings.append(
                'Pasted Authentication-Results reports a failed SPF, DKIM, or DMARC check; '
                'header text is unverified and can be forged.'
            )

    urls = _extract_urls(content)
    if urls:
        url_results = []
        for url in urls[:MAX_URLS]:
            result = scan_url(url)  # Static analysis only. No HTTP request.
            if result['risk'] != 'Invalid':
                url_results.append((url, result))

        high = [(url, result) for url, result in url_results
                if result['score'] >= 25]
        if high:
            highest_url_score = max(result['score'] for _, result in high)
            url_points = 35 if highest_url_score >= 75 else (25 if highest_url_score >= 50 else 15)
            score += url_points  # One bounded URL contribution per email.
            for url, result in high[:3]:
                findings.append(
                    f'Embedded URL host {_safe_hostname(url)} triggered '
                    f'{result["risk"].lower()}-level URL heuristics; do not open it without verification.'
                )
            if len(high) > 3:
                findings.append('Additional suspicious embedded URLs were found.')
        else:
            findings.append('Embedded links were found; none triggered elevated basic URL heuristics.')

        if len(urls) > MAX_URLS:
            findings.append(f'Only the first {MAX_URLS} unique URLs were scanned.')

    score = min(score, 100)
    if not findings:
        findings.append('No indicators matched the current text, header, or URL rules.')

    return {"score": score, "risk": _risk_label(score), "findings": findings}
