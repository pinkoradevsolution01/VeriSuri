import unittest

from backend.app.services.rules import url_signals
from backend.app.schemas import LinkIntelligence
from backend.app.services.url_intelligence import extract_url, intelligence_risk_signals, is_official_domain, normalize_url


class UrlSafetyTests(unittest.TestCase):
    def test_extracts_link_from_pasted_message(self):
        url, extracted = extract_url("Verify now at https://bdoph.me/login. Do not delay")
        self.assertTrue(extracted)
        self.assertEqual(url, "https://bdoph.me/login")

    def test_extracts_defanged_link_from_pasted_message(self):
        url, extracted = extract_url(r"Verify now at hxxps://bdo[.]example/login. Do not delay")
        self.assertTrue(extracted)
        self.assertEqual(url, "https://bdo.example/login")

    def test_official_domain_requires_a_label_boundary(self):
        self.assertTrue(is_official_domain("www.bdo.com.ph"))
        self.assertFalse(is_official_domain("evilbdo.com.ph"))
        signals, score = url_signals("https://evilbdo.com.ph/login")
        self.assertIn("May imitate a Philippine financial brand", signals)
        self.assertGreaterEqual(score, 38)

    def test_flags_new_scam_style_url_without_a_feed_match(self):
        signals, score = url_signals("https://gca5h-security.top/verify?redirect=https%3A%2F%2Fexample.com")
        self.assertIn("Domain label closely resembles the GCASH brand", signals)
        self.assertIn("URL path or query contains account or reward lure terms", signals)
        self.assertIn("Contains a redirect parameter that can obscure the final destination", signals)
        self.assertGreaterEqual(score, 50)

    def test_passive_destination_evidence_increases_caution(self):
        intelligence = LinkIntelligence(
            canonical_host="unfamiliar.example",
            redirect_hosts=["other.example"],
            domain_age_days=12,
        )
        signals, score = intelligence_risk_signals(intelligence)
        self.assertIn("Domain registration evidence suggests a very new domain (under 30 days old)", signals)
        self.assertIn("Server-side redirect inspection changed the destination host", signals)
        self.assertGreaterEqual(score, 42)

    def test_malformed_url_is_safe_to_reject(self):
        host, canonical = normalize_url("https://[bad-host")
        self.assertEqual((host, canonical), ("", ""))
        signals, score = url_signals("https://[bad-host")
        self.assertEqual(signals, ["The URL has no valid hostname"])
        self.assertEqual(score, 90)


if __name__ == "__main__":
    unittest.main()
