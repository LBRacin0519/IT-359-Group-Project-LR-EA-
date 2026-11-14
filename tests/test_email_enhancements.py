"""Run with python tests/test_email_enhancements.py from repository root."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from scanners.email_scanner import scan_email


class EmailEnhancementTests(unittest.TestCase):
    def test_existing_urgency_score_unchanged(self):
        self.assertEqual(scan_email('urgent')['score'], 15)

    def test_existing_password_score_unchanged(self):
        self.assertEqual(scan_email('enter your password')['score'], 25)

    def test_existing_test_email(self):
        self.assertEqual(scan_email('URGENT: Verify your account immediately and enter your password.')['score'], 40)

    def test_blank_invalid(self):
        self.assertEqual(scan_email('   ')['risk'], 'Invalid')

    def test_large_input_invalid(self):
        self.assertEqual(scan_email('a'*100001)['risk'], 'Invalid')

    def test_mismatched_reply_to(self):
        mail = 'From: Staff <staff@school.edu>\nReply-To: billing@other.test\nSubject: Hello\n\nHi'
        self.assertEqual(scan_email(mail)['score'], 20)

    def test_related_reply_to(self):
        mail = 'From: Staff <staff@school.edu>\nReply-To: support@mail.school.edu\n\nHi'
        self.assertEqual(scan_email(mail)['score'], 0)

    def test_authentication_fail(self):
        mail = 'From: hi@example.org\nAuthentication-Results: mx.test; dmarc=fail\n\nHello'
        self.assertEqual(scan_email(mail)['score'], 25)

    def test_authentication_pass_not_a_detection(self):
        mail = 'From: hi@example.org\nAuthentication-Results: mx.test; spf=pass; dkim=pass\n\nHello'
        self.assertEqual(scan_email(mail)['score'], 0)

    def test_suspicious_ip_url(self):
        result = scan_email('Look here: http://198.51.100.2/login/verify')
        self.assertEqual(result['score'], 25)
        self.assertTrue(any('Embedded URL host' in f for f in result['findings']))

    def test_html_href_extracted(self):
        result = scan_email('<a href="http://198.51.100.2/login/verify">Click</a>')
        self.assertEqual(result['score'], 25)

    def test_safe_url_does_not_raise_score(self):
        result = scan_email('Here: https://example.org/')
        self.assertEqual(result['score'], 0)

    def test_urls_do_not_trigger_network_requests(self):
        with patch('requests.get', side_effect=AssertionError('Network call')) as get, \
             patch('requests.post', side_effect=AssertionError('Network call')) as post:
            scan_email('Check: http://198.51.100.2/login/verify')
            get.assert_not_called()
            post.assert_not_called()

    def test_only_first_ten_urls_scanned(self):
        links = ' '.join(f'https://example{i}.org/' for i in range(12))
        result = scan_email(links)
        self.assertTrue(any('first 10' in f for f in result['findings']))

    def test_raw_link_token_not_sent_as_finding(self):
        r = scan_email('http://198.51.100.2/login/verify?token=PRIVATESECRET')
        self.assertNotIn('PRIVATESECRET', ' '.join(r['findings']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
