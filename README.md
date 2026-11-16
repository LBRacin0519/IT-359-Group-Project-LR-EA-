# Sn00py Bl0ck3r

**IT 359 — AI-assisted cybersecurity triage (Python + Streamlit)**

Sn00py Bl0ck3r provides non-executing, **local heuristic** checks for URLs, QR-code links, pasted emails, and uploaded files. A user can request an optional human-readable explanation through the Illinois State University Sushi AI service. SQLite preserves a local record of scan scores and sanitized findings.

This is an educational triage tool for **realistic demonstrations and preliminary review**, not antivirus software, a real-time threat feed, a verified phishing verdict, or a substitute for security personnel.

## Features

| Tab | Features | Important limitations |
|---|---|---|
| URL | HTTPS/HTTP, IP destinations, `@` userinfo, shortened URLs, punycode, keywords, long addresses, unusual ports and subdomains | URL is never visited or DNS-resolved. No live reputation verification |
| QR Code | Decode PNG/JPEG images with OpenCV, inspect HTTP(S) decoded URLs | Text-only QR payloads can be decoded but are not assigned URL risk scores |
| Email | Phishing phrases, optional pasted headers, `From` vs `Reply-To`, reported SPF/DKIM/DMARC failures, HTML hyperlink mismatch, embedded URLs, attachment filenames | Headers aren't cryptographically verified; no mail-server access, inbox integration or attachment download |
| File | Local SHA-256, file-header checks, extension mismatch, double extensions, PDF action markers, ZIP central-directory metadata | No execution, archive decompression, full PDF interpretation, malware signatures or sandboxing |
| History | SQLite persistence, filters, counts, latest results, CSV export | Per-machine local storage; the SQLite database is not uploaded to GitHub |

Each scanner returns a `score` (0–100), a `risk` (`Low`, `Medium`, `High`, `Critical` or `Invalid`), and a list of explainable findings. These scores represent rule-weighted indicators **not probabilities of malware**. False positives and false negatives are possible.

## Folder structure

```text
src/app.py                     Streamlit five-tab interface
src/scanners/url_scanner.py    Static URL checks
src/scanners/qr_scanner.py     Local QR decoding
src/scanners/email_scanner.py  Phishing text/header/link checks
src/scanners/file_scanner.py   Local, static file inspection
src/core/ai_analyzer.py       Optional Sushi AI explanations
src/core/database.py          SQLite scan history
tests/test_security_upgrade.py Offline unittest suite
```

## Windows PowerShell installation

```powershell
cd "$HOME\Documents\IT-359-Group-Project-LR-EA-"
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run src/app.py
```

If `.venv` already exists, activate it without recreating the environment. If PowerShell blocks activation, launch with `\.venv\Scripts\python.exe -m streamlit run src/app.py`.

Open the locally displayed Streamlit URL, commonly `http://localhost:8501`.

## Optional Sushi AI

To obtain **real** `gpt-oss:latest` explanations, use your own approved Sushi AI account and university network or VPN. In the same terminal used to launch Streamlit:

```powershell
$env:SUSHI_API_KEY = Read-Host "Sushi AI API key" -MaskInput
$env:SUSHI_MOCK_MODE = "false"
python -m streamlit run src/app.py
```

Otherwise, AI mode defaults to **offline**, displaying clearly labeled local demonstrations. The scanner still calculates risk independently of AI.

The university documentation uses an **HTTP** endpoint (`http://sushi.it.ilstu.edu:8080/api/chat/completions`). HTTP does not provide end-to-end TLS. Follow your university's approved access policy, and never submit sensitive content. The app sends only bounded scanner findings, score, risk level and type, not raw emails, full submitted URLs, file bytes, QR images or file hashes. It does not automatically contact Sushi AI during local scanning—only when an AI explanation button is pressed in live mode.

## Realistic demonstration samples (all harmless)

- **URL:** compare `https://example.com` and `http://192.0.2.55/login` (documentation-only IP address).
- **QR:** generate a QR code for `https://example.com` using `qrcode` or your existing test QR image.
- **Email:** paste a fictional urgent account-lock message with differing `From` and `Reply-To` domains and an embedded sample URL.
- **File:** compare a plain `notes.txt` with synthetic `invoice.pdf.exe` bytes beginning with `MZ`, or make a ZIP containing a dummy `invoice.exe` name. Never execute any test payload.
- **History:** view filters and export only the permitted scan metadata to CSV.

## Run regression tests

```powershell
python -m unittest discover -s tests -p "test_security_upgrade.py" -v
```

Tests use dummy, harmless bytes and never send external requests. Always test Streamlit functionality separately after upgrading.

## Privacy and safety

- The local database (`data/scan_history.sqlite3`) is automatically excluded by the existing `.gitignore` pattern. It records sanitized findings, UTC time, score, and category; it omits full inputs and credentials.
- User-selected files are read locally in memory (max 15 MiB for scans); the app never runs or extracts them. Uploaded files may still be malicious if opened outside this app.
- Some risk indicators occur in legitimate contexts. A low score never guarantees safety; a Critical score is not definitive proof of malware.
- A ZIP member filename is not the same as reading the embedded file's code. PDF marker detection is not comprehensive document analysis. Headers in pasted emails can be spoofed.
- The only optional external call is to Sushi AI, when explicitly requested. No third-party reputation service is included.
- CSV exports contain the recorded findings and should be reviewed before sharing.

## Submission items still needed

Provide course-required PDF report and presentation in `docs/`; run the application on both team members' PCs, collect screenshots of testing, review known limitations, verify the repo is public, and rehearse a live demo with offline fallback. Confirm final format and deadlines with the instructor's current assignment instructions.
