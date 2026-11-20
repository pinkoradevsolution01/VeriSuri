import unittest

from backend.app.services.rules import url_signals
from backend.app.services.url_intelligence import extract_url, is_official_domain, normalize_url


class UrlSafetyTests(unittest.TestCase):
    def test_extracts_link_from_pasted_message(self):
        url, extracted = extract_url("Verify now at https://bdoph.me/login. Do not delay")
        self.assertTrue(extracted)
        self.assertEqual(url, "https://bdoph.me/login")

    def test_official_domain_requires_a_label_boundary(self):
        self.assertTrue(is_official_domain("www.bdo.com.ph"))
        self.assertFalse(is_official_domain("evilbdo.com.ph"))
        signals, score = url_signals("https://evilbdo.com.ph/login")
        self.assertIn("May imitate a Philippine financial brand", signals)
        self.assertGreaterEqual(score, 38)

    def test_malformed_url_is_safe_to_reject(self):
        host, canonical = normalize_url("https://[bad-host")
        self.assertEqual((host, canonical), ("", ""))
        signals, score = url_signals("https://[bad-host")
        self.assertEqual(signals, ["The URL has no valid hostname"])
        self.assertEqual(score, 90)


if __name__ == "__main__":
    unittest.main()
