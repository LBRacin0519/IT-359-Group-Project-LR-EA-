"""Local email phishing triage; never fetches email links or attachments."""

import re
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

from scanners.url_scanner import scan_url, risk_label

MAX_EMAIL_CHARS = 100_000
MAX_LINKS = 10
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
HEADER_RE = re.compile(r'^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$')
HEADER_STARTS = ("from:", "to:", "reply-to:", "return-path:", "subject:", "date:", "authentication-results:")
# Accept both MIME header attributes and pasted email attachment labels.
# This inspects filenames only; attachment contents are never opened.
RISKY_ATTACHMENT_RE = re.compile(
    r"\b(?:"
    r"(?:filename|name)\s*=\s*[\"']?"
    r"|(?:attachment|attached file)\s*:\s*[\"']?"
    r")"
    r"(?P<filename>[^\s;\"'<>]+\.(?:exe|scr|js|vbs|ps1|bat|cmd|hta|docm|xlsm|pptm))\b",
    re.I,
)


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self._href = None
        self._anchor_text = []
        self.mismatches = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._href = dict(attrs).get("href")
            self._anchor_text = []
            if isinstance(self._href, str) and self._href.lower().startswith(("http://", "https://")):
                self.links.append(self._href)

    def handle_data(self, data):
        if self._href is not None:
            self._anchor_text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href:
            shown = "".join(self._anchor_text).strip()
            if shown.lower().startswith(("http://", "https://")):
                try:
                    real_host = urlsplit(self._href).hostname
                    claimed_host = urlsplit(shown).hostname
                    if real_host and claimed_host and real_host.lower() != claimed_host.lower():
                        self.mismatches += 1
                except ValueError:
                    pass
            self._href = None
            self._anchor_text = []


def _headers(raw):
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    block, sep, _ = normalized.partition("\n\n")
    if not sep or len(block) > 8192:
        return {}
    lines = block.split("\n")
    if not lines or not lines[0].lower().startswith(HEADER_STARTS):
        return {}
    parsed = {}
    last = None
    for line in lines:
        if line.startswith((" ", "\t")) and last:
            parsed[last][-1] += " " + line.strip()
            continue
        match = HEADER_RE.match(line)
        if not match:
            return {}
        last = match.group(1).lower()
        parsed.setdefault(last, []).append(match.group(2).strip())
    return parsed


def _domain(address):
    parsed = parseaddr(address)[1]
    if parsed.count("@") != 1:
        return None
    return parsed.rsplit("@", 1)[1].lower().rstrip(".")


def _related_domains(a, b):
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _links(text, parser):
    seen = set()
    results = []
    for candidate in list(parser.links) + [m.group(0).rstrip(".,;!?)>]") for m in URL_RE.finditer(text)]:
        if candidate not in seen:
            seen.add(candidate)
            results.append(candidate)
    return results


def scan_email(content):
    """Analyze pasted email text, optional headers, HTML links, and social engineering.

    All findings omit the raw email, sender addresses, and complete URLs.
    """
    if not isinstance(content, str) or not content.strip():
        return {"score": 0, "risk": "Invalid", "findings": ["No email content provided."]}
    if len(content) > MAX_EMAIL_CHARS:
        return {"score": 0, "risk": "Invalid", "findings": ["Email exceeds the 100,000-character limit."]}

    findings = []
    score = 0
    rules = (
        (r"\b(urgent|immediately|act now|within 24 hours)\b", 15, "Urgency language may pressure the recipient to act quickly."),
        (r"\b(verify your account|confirm your password|enter your password|send your password)\b", 25, "Message requests account verification or password-related action."),
        (r"\b(account suspended|account will be closed|account will be locked)\b", 20, "Message threatens loss of account access."),
        (r"\b(gift cards?|wire transfer|send bitcoin|crypto payment)\b", 20, "Message mentions payment methods often used in scams."),
        (r"\b(you have won|claim your prize|lottery winner)\b", 20, "Message uses prize or lottery language."),
    )
    for regex, points, description in rules:
        if re.search(regex, content, flags=re.I):
            score += points
            findings.append(description)

    headers = _headers(content)
    if headers:
        from_domain = _domain(headers.get("from", [""])[0])
        reply_domain = _domain(headers.get("reply-to", [""])[0])
        if from_domain and reply_domain and not _related_domains(from_domain, reply_domain):
            score += 20
            findings.append("From and Reply-To domains differ; independently verify sender identity.")
        auth = " ".join(headers.get("authentication-results", []))
        if re.search(r'\b(?:spf|dkim|dmarc)\s*=\s*(?:fail|hardfail|softfail)\b', auth, re.I):
            score += 25
            findings.append("Pasted authentication headers report SPF/DKIM/DMARC failure; pasted headers are not independently verified.")

    parser = _LinkParser()
    try:
        parser.feed(content)
    except (ValueError, AssertionError):
        pass
    if parser.mismatches:
        score += 30
        findings.append("An HTML link displays a different website hostname from its actual destination.")
    links = _links(content, parser)
    if links:
        results = [scan_url(link) for link in links[:MAX_LINKS]]
        valid_scores = [r["score"] for r in results if r["risk"] != "Invalid"]
        highest = max(valid_scores, default=0)
        if highest >= 50:
            score += 30
            findings.append("An embedded URL triggers High/Critical static URL indicators.")
        elif highest >= 25:
            score += 15
            findings.append("An embedded URL triggers Medium static URL indicators.")
        else:
            findings.append("Embedded links were found; none triggered elevated URL heuristics.")
        if len(links) > MAX_LINKS:
            findings.append(f"Only the first {MAX_LINKS} unique links were analyzed.")

    attachment_match = RISKY_ATTACHMENT_RE.search(content)
    if attachment_match:
        attachment_name = attachment_match.group("filename").lower()
        # Filename only: do not save, display, or send the full filename to AI.
        if re.search(
            r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(?:exe|scr|js|vbs|ps1|bat|cmd|hta)$",
            attachment_name,
        ):
            score += 60
            findings.append(
                "A referenced attachment uses a deceptive document/image-to-executable double extension; "
                "attachment bytes were not examined."
            )
        elif attachment_name.endswith((".docm", ".xlsm", ".pptm")):
            score += 35
            findings.append(
                "A referenced attachment uses a macro-enabled Office format; "
                "attachment bytes were not examined."
            )
        else:
            score += 50
            findings.append(
                "A referenced attachment has an executable or script extension; "
                "attachment bytes were not examined."
            )

    score = min(score, 100)
    if not findings:
        findings.append("No indicators matched these text, header, and URL checks; this does not prove safety.")
    return {"score": score, "risk": risk_label(score), "findings": findings}
