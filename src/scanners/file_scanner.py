"""Heuristic, static file inspection. Never executes uploaded content.

This scanner intentionally does NOT unpack archives, contact reputation services,
or claim that a low-risk score proves a file is safe.
"""

import hashlib
from pathlib import Path

MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MiB, local demonstration cap
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
    ".jar", ".lnk", ".sh",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
DISGUISE_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"}


def _file_signature(data):
    """Infer a few formats from prefixes; not full file validation."""
    if data.startswith(b"MZ"):
        return "MZ executable-style header", {".exe", ".dll", ".scr", ".com", ".sys"}, True
    if data.startswith(b"\x7fELF"):
        return "ELF executable header", {".elf", ".so", ".bin"}, True
    if data.startswith(b"%PDF-"):
        return "PDF header", {".pdf"}, False
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG header", {".png"}, False
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG header", {".jpg", ".jpeg"}, False
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF header", {".gif"}, False
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return (
            "ZIP container header (including some Office document formats)",
            {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"},
            False,
        )
    return "Unrecognized by limited signature checks", None, False


def _risk_label(score):
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _invalid(message):
    return {"score": 0, "risk": "Invalid", "findings": [message]}


def scan_file(filename, data):
    """Analyze uploaded bytes without executing or transmitting them.

    Returns a dict compatible with email / URL scanner risk display.
    SHA-256 is output as metadata, not included in AI findings.
    """
    if not isinstance(filename, str) or not filename.strip():
        return _invalid("A filename is required.")
    if not isinstance(data, bytes) or not data:
        return _invalid("No file bytes provided.")
    if len(data) > MAX_FILE_SIZE:
        return _invalid("File exceeds the 15 MiB static-analysis limit.")

    # Uploaded names can include Windows or Unix path separators.
    name = Path(filename.replace("\\", "/")).name
    extension = Path(name).suffix.lower()
    file_type, matching_extensions, executable_header = _file_signature(data)
    score = 0
    findings = [
        f"Filename extension: {extension or '(none)'}. ",
        f"Header inspection: {file_type}.",
    ]

    if extension in EXECUTABLE_EXTENSIONS:
        score += 50
        findings.append("Extension is associated with executable code, scripts, or shortcuts.")
    elif extension in MACRO_EXTENSIONS:
        score += 35
        findings.append("Office file extension indicates a macro-enabled document format.")

    parts = name.lower().split(".")
    if (
        len(parts) >= 3
        and "." + parts[-2] in DISGUISE_EXTENSIONS
        and extension in EXECUTABLE_EXTENSIONS
    ):
        score += 30
        findings.append("Double extension may make executable content look like a document or image.")

    if executable_header:
        score += 40
        findings.append("Header begins with a recognizable executable marker; full format was not validated.")

    if matching_extensions is not None and extension not in matching_extensions:
        score += 30
        findings.append("Filename extension differs from the detected header format.")

    if extension in {".html", ".htm", ".svg"}:
        score += 15
        findings.append("Web-format files may contain active content or external references.")

    if score == 0:
        findings.append("No elevated-risk indicators matched these limited checks; this does not establish safety.")

    score = min(score, 100)
    return {
        "filename": name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_type": file_type,
        "score": score,
        "risk": _risk_label(score),
        "findings": findings,
    }
