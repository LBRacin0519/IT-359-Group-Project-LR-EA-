"""Offline regression suite: python -m unittest discover -s tests -v.

Runs only synthetic data. It never contacts Sushi AI or any URL.
"""

import hashlib
import io
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from core import database
from core.ai_analyzer import analyze_with_ai
from scanners.url_scanner import scan_url
from scanners.email_scanner import scan_email
from scanners.file_scanner import scan_file, MAX_FILE_SIZE
from scanners.qr_scanner import decode_qr


class URLTests(unittest.TestCase):
    def test_suspicious_url(self):
        r = scan_url("http://192.0.2.55/login")
        self.assertEqual((r["score"], r["risk"]), (60, "High"))

    def test_clean_url(self):
        self.assertEqual(scan_url("https://example.com")["risk"], "Low")

    def test_invalid_scheme(self):
        self.assertEqual(scan_url("file:///etc/passwd")["risk"], "Invalid")

    def test_blank(self):
        self.assertEqual(scan_url("")["risk"], "Invalid")

    def test_whitespace(self):
        self.assertEqual(scan_url("https://exa mple.com")["risk"], "Invalid")

    def test_userinfo(self):
        r = scan_url("https://example.com@malicious.test/login")
        self.assertTrue(any("userinfo" in finding for finding in r["findings"]))

    def test_punycode(self):
        self.assertTrue(any("punycode" in f for f in scan_url("https://xn--e1afmkfd.example/")["findings"]))

    def test_short_link(self):
        self.assertGreater(scan_url("https://bit.ly/abcdef")["score"], 0)

    def test_nonstandard_port(self):
        self.assertGreater(scan_url("https://example.com:4444/login")["score"], 0)

    def test_long_url(self):
        self.assertTrue(any("unusually long" in f for f in scan_url("https://example.com/" + "a" * 160)["findings"]))

    def test_query_secret_not_exposed(self):
        result = scan_url("https://example.com/reset?token=secret-private-123")
        self.assertNotIn("secret-private-123", " ".join(result["findings"]))

    def test_url_never_connects(self):
        with patch("requests.get", side_effect=AssertionError("GET sent")), patch("requests.post", side_effect=AssertionError("POST sent")):
            scan_url("http://192.0.2.55/login")


class EmailTests(unittest.TestCase):
    def test_demo(self):
        result = scan_email("URGENT: Your account will be locked within 24 hours. Please verify your account and confirm your password immediately.")
        self.assertEqual((result["score"], result["risk"]), (60, "High"))

    def test_blank(self):
        self.assertEqual(scan_email("   ")["risk"], "Invalid")

    def test_header_domain_mismatch(self):
        result = scan_email("From: A <a@school.edu>\nReply-To: fraud@outside.test\nSubject: Notice\n\nHello")
        self.assertEqual(result["score"], 20)

    def test_related_domains(self):
        result = scan_email("From: A <a@school.edu>\nReply-To: support@mail.school.edu\n\nHello")
        self.assertEqual(result["score"], 0)

    def test_spf_fail_is_unverified(self):
        r = scan_email("From: A <a@example.test>\nAuthentication-Results: mx; spf=fail\n\nHi")
        self.assertEqual(r["score"], 25)
        self.assertTrue(any("not independently verified" in f for f in r["findings"]))

    def test_html_link_mismatch(self):
        r = scan_email('<a href="https://wrong.test/login">https://example.com</a>')
        self.assertTrue(any("different website hostname" in f for f in r["findings"]))

    def test_embedded_link(self):
        r = scan_email("Please visit http://192.0.2.55/login")
        self.assertTrue(any("embedded URL" in f for f in r["findings"]))

    def test_no_raw_query_in_findings(self):
        r = scan_email("Visit https://example.com/login?token=TOPSECRET123")
        self.assertNotIn("TOPSECRET123", " ".join(r["findings"]))

    def test_attachment_name_detection(self):
        r = scan_email('Content-Disposition: attachment; filename="invoice.exe"')
        self.assertTrue(any("attachment" in f for f in r["findings"]))

    def test_plaintext_attachment_label(self):
        result = scan_email('Attachment: account_update.pdf.exe')
        self.assertEqual(result['score'], 60)
        self.assertTrue(any('double extension' in f for f in result['findings']))

    def test_quoted_attachment_label(self):
        result = scan_email('Attachment: "report.docm"')
        self.assertEqual(result['score'], 35)
        self.assertTrue(any('macro-enabled' in f for f in result['findings']))

    def test_email_never_connects(self):
        with patch("requests.get", side_effect=AssertionError("GET sent")), patch("requests.post", side_effect=AssertionError("POST sent")):
            scan_email("Visit http://192.0.2.55/login")


class FileTests(unittest.TestCase):
    def test_plain_text(self):
        self.assertEqual(scan_file("notes.txt", b"Hello")["risk"], "Low")

    def test_fake_double_extension(self):
        r = scan_file("invoice.pdf.exe", b"MZ" + bytes(64))
        self.assertEqual((r["score"], r["risk"]), (100, "Critical"))
        self.assertTrue(any("Double extension" in f for f in r["findings"]))

    def test_sha256(self):
        data = b"%PDF-1.4\nExample"
        self.assertEqual(scan_file("report.pdf", data)["sha256"], hashlib.sha256(data).hexdigest())

    def test_mismatched_header(self):
        self.assertEqual(scan_file("photo.png", b"%PDF-1.4\nTest")["risk"], "Medium")

    def test_pdf_action(self):
        r = scan_file("report.pdf", b"%PDF-1.4\n/JavaScript (test)")
        self.assertTrue(any("JavaScript" in f for f in r["findings"]))

    def _zip(self, entries):
        out = io.BytesIO()
        with zipfile.ZipFile(out, "w") as z:
            for name, data in entries:
                z.writestr(name, data)
        return out.getvalue()

    def test_zip_executable(self):
        r = scan_file("archive.zip", self._zip([("invoice.exe", b"dummy")]))
        self.assertTrue(any("executable/script" in f for f in r["findings"]))
        self.assertEqual((r["score"], r["risk"]), (35, "Medium"))
        self.assertTrue(any("not inspected or executed" in f for f in r["findings"]))

    def test_zip_without_executable(self):
        r = scan_file("archive.zip", self._zip([("readme.txt", b"hello")]))
        self.assertEqual((r["score"], r["risk"]), (0, "Low"))

    def test_zip_executable_not_classified_malware(self):
        r = scan_file("archive.zip", self._zip([("installer.exe", b"just text")]))
        self.assertFalse(any("malware detected" in f.lower() for f in r["findings"]))

    def test_zip_macro(self):
        r = scan_file("document.docm", self._zip([("word/vbaProject.bin", b"dummy")]))
        self.assertTrue(any("VBA" in f for f in r["findings"]))

    def test_zip_traversal(self):
        r = scan_file("archive.zip", self._zip([("../evil.txt", b"dummy")]))
        self.assertTrue(any("traversal" in f for f in r["findings"]))

    def test_no_file_execution(self):
        with patch("subprocess.run", side_effect=AssertionError("EXECUTED")), patch("requests.post", side_effect=AssertionError("POST sent")):
            scan_file("archive.zip", self._zip([("invoice.exe", b"dummy")]))

    def test_empty(self):
        self.assertEqual(scan_file("empty.txt", b"")["risk"], "Invalid")

    def test_large(self):
        self.assertEqual(scan_file("large.zip", b"a" * (MAX_FILE_SIZE + 1))["risk"], "Invalid")

    def test_filename_not_in_findings(self):
        r = scan_file("confidential-12345.pdf", b"%PDF-1.7")
        self.assertNotIn("confidential-12345", " ".join(r["findings"]))


class QRTests(unittest.TestCase):
    def test_empty(self):
        self.assertFalse(decode_qr(b"")["success"])

    def test_invalid(self):
        self.assertFalse(decode_qr(b"this is not an image")["success"])

    def test_oversized(self):
        self.assertFalse(decode_qr(b"a" * (8 * 1024 * 1024 + 1))["success"])

    def test_real_qr(self):
        import qrcode
        img = qrcode.make("https://example.com")
        with io.BytesIO() as out:
            img.save(out, format="PNG")
            decoded = decode_qr(out.getvalue())
        self.assertTrue(decoded["success"])
        self.assertEqual(decoded["content"], "https://example.com")


class AITests(unittest.TestCase):
    def test_mock_mode_no_network(self):
        with patch.dict(os.environ, {"SUSHI_MOCK_MODE": "true"}), patch("requests.post", side_effect=AssertionError("POST sent")):
            r = analyze_with_ai("URL", 60, "High", ["URL uses HTTP."])
        self.assertTrue(r["success"])
        self.assertTrue(r["explanation"].startswith("[OFFLINE TEST"))

    def test_live_mode_missing_key_no_network(self):
        with patch.dict(os.environ, {"SUSHI_MOCK_MODE": "false", "SUSHI_API_KEY": ""}), patch("requests.post") as send:
            r = analyze_with_ai("URL", 60, "High", ["A finding."])
        self.assertFalse(r["success"])
        send.assert_not_called()


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self._patch = patch.object(database, "DATABASE_PATH", Path(self.temp.name) / "scan_history.sqlite3")
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self.temp.cleanup()

    def test_create_save_get(self):
        record_id = database.save_scan("URL", {"score": 60, "risk": "High", "findings": ["HTTP detected"]})
        result = database.get_recent_scans(5)
        self.assertEqual(record_id, 1)
        self.assertEqual(result[0]["score"], 60)
        self.assertEqual(database.count_scans(), 1)

    def test_invalid_score_rejected(self):
        with self.assertRaises(ValueError):
            database.save_scan("URL", {"score": 500, "risk": "High", "findings": []})

    def test_no_raw_url_saved(self):
        record = {"score": 0, "risk": "Low", "findings": ["No significant indicators."]}
        database.save_scan("URL", record)
        content = database.DATABASE_PATH.read_bytes()
        self.assertNotIn(b"https://example.com/private", content)


if __name__ == "__main__":
    unittest.main(verbosity=2)
