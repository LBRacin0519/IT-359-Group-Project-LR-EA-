"""Sn00py Bl0ck3r: static file checks; no execution or decompression."""

import hashlib
import io
import re
import struct
import zipfile
from pathlib import Path

from scanners.url_scanner import risk_label

MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MiB
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".msi", ".bat", ".cmd",
    ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".jar",
    ".lnk", ".sh", ".py",
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
DISGUISE_EXTENSIONS = {".pdf", ".doc", ".docx", ".txt", ".jpg", ".jpeg", ".png", ".xlsx"}
ZIP_EXTENSIONS = {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".odt", ".ods", ".odp"}


def _detect(data):
    if data.startswith(b"MZ"):
        # The MZ prefix alone does NOT establish a valid PE binary.
        valid_pe = False
        if len(data) >= 64:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            valid_pe = pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00"
        return ("PE executable header" if valid_pe else "MZ prefix (PE unverified)",
                {".exe", ".dll", ".scr", ".com", ".sys"}, 30 if valid_pe else 20)
    patterns = (
        (b"\x7fELF", "ELF binary header", {".elf", ".so", ".bin"}, 30),
        (b"%PDF-", "PDF document header", {".pdf"}, 0),
        (b"\x89PNG\r\n\x1a\n", "PNG image header", {".png"}, 0),
        (b"\xff\xd8\xff", "JPEG image header", {".jpg", ".jpeg"}, 0),
        (b"GIF87a", "GIF image header", {".gif"}, 0),
        (b"GIF89a", "GIF image header", {".gif"}, 0),
        (b"PK\x03\x04", "ZIP container header", ZIP_EXTENSIONS, 0),
        (b"PK\x05\x06", "Empty ZIP container header", ZIP_EXTENSIONS, 0),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document header", {".doc", ".xls", ".ppt", ".msi"}, 0),
        (b"7z\xbc\xaf\x27\x1c", "7z archive header", {".7z"}, 0),
        (b"Rar!\x1a\x07", "RAR archive header", {".rar"}, 0),
        (b"\x1f\x8b", "gzip archive header", {".gz", ".tgz"}, 0),
    )
    for signature, file_type, extensions, executable_points in patterns:
        if data.startswith(signature):
            return file_type, extensions, executable_points
    return "Unrecognized by limited signature checks", None, 0


def _zip_indicators(data):
    """Inspect ZIP metadata only; never read or extract archive members."""
    findings, points = [], 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()[:2001]
            if len(infos) > 1000:
                points += 10
                findings.append("Archive has more than 1,000 entries; inspection was limited.")
            lower_names = [info.filename.lower().replace("\\", "/") for info in infos]
            if any(name.endswith("vbaproject.bin") for name in lower_names):
                points += 40
                findings.append("Office-style archive includes a VBA macro project.")
            if any(Path(name).suffix in EXECUTABLE_EXTENSIONS for name in lower_names):
                # An executable/script name inside an archive warrants review,
                # but metadata alone does not establish that it is malicious.
                # Score this as Medium rather than treating it as harmless.
                points += 35
                findings.append(
                    "Archive contains executable/script-named entries; "
                    "member contents were not inspected or executed."
                )
            if any(name.startswith("/") or "../" in name or name == ".." for name in lower_names):
                points += 25
                findings.append("Archive contains a potentially unsafe traversal or absolute member path.")
            if any(info.flag_bits & 1 for info in infos):
                points += 10
                findings.append("Archive contains encrypted entries that could not be inspected.")
            if any(info.file_size >= 1024 * 1024 and info.compress_size > 0 and
                   info.file_size / info.compress_size > 100 for info in infos):
                points += 20
                findings.append("Archive metadata shows extreme compression ratio; expansion was not attempted.")
    except (zipfile.BadZipFile, ValueError, OSError, RuntimeError):
        points += 10
        findings.append("ZIP header was recognized but archive metadata could not be parsed.")
    return points, findings


def scan_file(filename, data):
    """Return metadata and heuristic risk findings for a user-selected file.

    File contents stay local; only sanitized findings may be passed to an AI.
    """
    if not isinstance(filename, str) or not filename.strip():
        return {"score": 0, "risk": "Invalid", "findings": ["A filename is required."]}
    if not isinstance(data, bytes) or not data:
        return {"score": 0, "risk": "Invalid", "findings": ["No file bytes provided."]}
    if len(data) > MAX_FILE_SIZE:
        return {"score": 0, "risk": "Invalid", "findings": ["File exceeds the 15 MiB static-analysis limit."]}

    clean_name = filename.replace("\\", "/").split("/")[-1]
    extension = Path(clean_name).suffix.lower()
    safe_extension = extension if re.fullmatch(r"\.[a-z0-9]{1,12}", extension) else "(unknown)"
    file_type, allowed_extensions, header_points = _detect(data)
    score = header_points
    findings = [f"Filename extension: {safe_extension}.", f"Detected header: {file_type}."]

    if extension in EXECUTABLE_EXTENSIONS:
        score += 50
        findings.append("Filename extension is associated with executable code or scripts.")
    elif extension in MACRO_EXTENSIONS:
        score += 35
        findings.append("File has a macro-enabled Office document extension.")

    parts = clean_name.lower().split(".")
    if len(parts) >= 3 and "." + parts[-2] in DISGUISE_EXTENSIONS and extension in EXECUTABLE_EXTENSIONS:
        score += 30
        findings.append("Double extension may disguise an executable as a document or image.")

    if allowed_extensions is not None and extension not in allowed_extensions:
        score += 30
        findings.append("Filename extension does not match detected signature.")

    if extension in {".html", ".htm", ".svg"}:
        score += 15
        findings.append("Web-format files can contain active content or external references.")

    if file_type == "PDF document header":
        # Heuristic markers only; parsing PDF safely requires dedicated tools.
        if re.search(rb"/(?:JavaScript|JS|OpenAction)\b", data[:1_000_000], re.I):
            score += 20
            findings.append("PDF contains JavaScript or automatic-action markers (not executed).")

    if file_type in ("ZIP container header", "Empty ZIP container header"):
        extra_points, extra_findings = _zip_indicators(data)
        score += extra_points
        findings.extend(extra_findings)

    score = min(score, 100)
    if score == 0:
        findings.append("No elevated-risk indicators matched these limited checks; this does not prove safety.")
    return {
        "filename": clean_name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_type": file_type,
        "score": score,
        "risk": risk_label(score),
        "findings": findings,
    }
