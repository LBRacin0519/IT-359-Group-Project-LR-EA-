import hashlib
import re
from pathlib import Path

MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MiB

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".msi",
    ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jse", ".wsf", ".hta", ".jar", ".lnk",
    ".sh", ".py"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm"
}

DISGUISE_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".txt",
    ".jpg", ".jpeg", ".png", ".xlsx"
}


def get_risk_level(score):
    if score >= 75:
        return "Critical"
    elif score >= 50:
        return "High"
    elif score >= 25:
        return "Medium"
    return "Low"


def detect_file_type(data):
    """
    Recognize common file signatures.
    A matching header does not validate the full file.
    """

    signatures = [
        (
            b"MZ",
            "Windows executable-style header",
            {".exe", ".dll", ".scr", ".com", ".sys"},
            True
        ),
        (
            b"\x7fELF",
            "Linux ELF executable header",
            {".elf", ".so", ".bin"},
            True
        ),
        (
            b"%PDF-",
            "PDF document header",
            {".pdf"},
            False
        ),
        (
            b"\x89PNG\r\n\x1a\n",
            "PNG image header",
            {".png"},
            False
        ),
        (
            b"\xff\xd8\xff",
            "JPEG image header",
            {".jpg", ".jpeg"},
            False
        ),
        (
            b"GIF89a",
            "GIF image header",
            {".gif"},
            False
        ),
        (
            b"GIF87a",
            "GIF image header",
            {".gif"},
            False
        ),
        (
            b"PK\x03\x04",
            "ZIP container header",
            {
                ".zip", ".jar", ".docx", ".xlsx",
                ".pptx", ".docm", ".xlsm", ".pptm"
            },
            False
        )
    ]

    for signature, name, extensions, executable in signatures:
        if data.startswith(signature):
            return name, extensions, executable

    return "Unknown or unrecognized header", None, False


def scan_file(filename, data):
    """
    Perform static security checks on an uploaded file.

    Returns metadata, score, risk, and findings.
    No file execution, network requests, or AI calls.
    """

    def invalid(message):
        return {
            "score": 0,
            "risk": "Invalid",
            "findings": [message]
        }

    # Validate input
    if not isinstance(filename, str) or not filename.strip():
        return invalid("A valid filename is required.")

    if not isinstance(data, bytes) or not data:
        return invalid("No file content was provided.")

    if len(data) > MAX_FILE_SIZE:
        return invalid("File exceeds the 15 MiB size limit.")

    # Extract filename without directory paths
    safe_name = filename.replace("\\", "/").split("/")[-1]
    extension = Path(safe_name).suffix.lower()

    # Keep untrusted filename characters out of AI findings
    display_extension = (
        extension
        if re.fullmatch(r"\.[a-z0-9]{1,12}", extension)
        else "(unrecognized)"
    )

    # Calculate file hash
    sha256_hash = hashlib.sha256(data).hexdigest()

    # Inspect file header
    file_type, matching_extensions, executable_header = (
        detect_file_type(data)
    )

    score = 0

    findings = [
        f"Filename extension: {display_extension}.",
        f"Detected header: {file_type}."
    ]

    # Rule 1: Suspicious executable or script extension
    if extension in EXECUTABLE_EXTENSIONS:
        score += 50
        findings.append(
            "File extension is associated with executable "
            "code, scripts, or shortcuts."
        )

    # Rule 2: Macro-enabled Office document
    if extension in MACRO_EXTENSIONS:
        score += 35
        findings.append(
            "Macro-enabled Office document extension detected."
        )

    # Rule 3: Potentially deceptive double extension
    name_parts = safe_name.lower().split(".")

    if len(name_parts) >= 3:
        previous_extension = "." + name_parts[-2]

        if (
            previous_extension in DISGUISE_EXTENSIONS
            and extension in EXECUTABLE_EXTENSIONS
        ):
            score += 30
            findings.append(
                "Potentially deceptive double extension detected."
            )

    # Rule 4: Executable-style file signature
    if executable_header:
        score += 25
        findings.append(
            "File starts with a recognizable executable header."
        )

    # Rule 5: Extension does not match detected signature
    if (
        matching_extensions is not None
        and extension not in matching_extensions
    ):
        score += 30
        findings.append(
            "Filename extension does not match the detected "
            "file header."
        )

    # Rule 6: Potentially active web content
    if extension in {".html", ".htm", ".svg"}:
        score += 15
        findings.append(
            "Web-format file may contain active content "
            "or external references."
        )

    # Cap score
    score = min(score, 100)
    risk = get_risk_level(score)

    if score == 0:
        findings.append(
            "No elevated-risk indicators were detected "
            "by the current static checks."
        )

    return {
        "filename": safe_name,
        "size_bytes": len(data),
        "sha256": sha256_hash,
        "file_type": file_type,
        "score": score,
        "risk": risk,
        "findings": findings
    }