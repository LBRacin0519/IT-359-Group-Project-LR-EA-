"""Local scanner smoke tests; run from repository root after applying patch.

Uses inert bytes only. No malware samples or network calls.
"""
import hashlib
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "src"))
from scanners.email_scanner import scan_email
from scanners.file_scanner import MAX_FILE_SIZE, scan_file
from core.ai_analyzer import analyze_with_ai


def check(condition, message):
    if not condition:
        raise AssertionError(message)


email = scan_email("URGENT: verify your account immediately and enter your password.")
check(email["score"] == 40 and email["risk"] == "Medium", "Email rule score")
check(scan_email(" ")["risk"] == "Invalid", "Blank email rejected")

pdf = b"%PDF-1.7\nsynthetic test content"
normal = scan_file("report.pdf", pdf)
check(normal["risk"] == "Low", "PDF header accepted")
check(normal["sha256"] == hashlib.sha256(pdf).hexdigest(), "SHA-256 correct")
check("sha256" in normal, "SHA-256 field exists")
check(not any(normal["sha256"] in finding for finding in normal["findings"]), "Hash excluded from AI findings")

# Synthetic marker: not an actual program and not executed.
dangerous = scan_file("invoice.pdf.exe", b"MZ" + bytes(64))
check(dangerous["score"] == 100 and dangerous["risk"] == "Critical", "Disguised executable scored")
check(any("Double extension" in f for f in dangerous["findings"]), "Double extension finding")

mismatch = scan_file("image.jpg", pdf)
check(mismatch["risk"] == "Medium", "Header/extension mismatch flagged")

macro = scan_file("invoice.docm", b"PK\x03\x04" + bytes(60))
check(macro["risk"] == "Medium", "Macro-enabled Office format flagged")

check(scan_file("empty.txt", b"")["risk"] == "Invalid", "Empty file rejected")
check(scan_file("large.pdf", b"Z" * (MAX_FILE_SIZE + 1))["risk"] == "Invalid", "Oversized file rejected")
check(scan_file("folder\\report.pdf", pdf)["filename"] == "report.pdf", "Path stripped")
check(scan_file("folder/report.pdf", pdf)["filename"] == "report.pdf", "Unix path stripped")

# Mock is explicitly selected so testing cannot contact Sushi.
os.environ["SUSHI_MOCK_MODE"] = "true"
for scan_type, result in (("Email", email), ("File", normal)):
    response = analyze_with_ai(scan_type, result["score"], result["risk"], result["findings"])
    check(response["success"], f"{scan_type} AI adapter mock success")
    check(response["explanation"].startswith("[OFFLINE TEST"), f"{scan_type} AI adapter mock mode")

print("PASS: email rule tests, 9 file checks, offline AI adapter for both tools")
