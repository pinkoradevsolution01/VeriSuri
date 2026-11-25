import unittest

from backend.app.services.rules import message_evidence, url_signals
from backend.app.schemas import LinkIntelligence
from backend.app.services.url_intelligence import UrlInputValidationError, extract_url, intelligence_risk_signals, is_official_domain, normalize_url, official_provider_for_host, validate_single_submitted_url
from backend.url_validation import url_release_failures
from backend.app.services.url_model import UrlPhishingModel


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
        self.assertEqual(official_provider_for_host("help.gotyme.com.ph"), "GoTyme Bank")
        signals, score = url_signals("https://evilbdo.com.ph/login")
        self.assertIn("May imitate a Philippine financial brand", signals)
        self.assertGreaterEqual(score, 38)

    def test_flags_new_scam_style_url_without_a_feed_match(self):
        signals, score = url_signals("https://gca5h-security.top/verify?redirect=https%3A%2F%2Fexample.com")
        self.assertIn("Domain label closely resembles the GCASH brand", signals)
        self.assertIn("URL path or query contains account or reward lure terms", signals)
        self.assertIn("Contains a redirect parameter that can obscure the final destination", signals)
        self.assertGreaterEqual(score, 50)

    def test_safety_advice_in_tagalog_does_not_become_a_credential_request(self):
        signals, score, _ = message_evidence("Huwag mong ibigay ang OTP, PIN, o password kahit kanino. Hindi ito hihingin ng bangko.")
        self.assertEqual(signals, [])
        self.assertEqual(score, 0)

    def test_search_query_keywords_do_not_become_a_url_lure_signal(self):
        signals, score = url_signals("https://www.google.com/search?q=account+verification")
        self.assertNotIn("URL path or query contains account or reward lure terms", signals)
        self.assertEqual(score, 0)

    def test_link_checker_rejects_multiple_or_malformed_links(self):
        with self.assertRaises(UrlInputValidationError):
            validate_single_submitted_url("https://google.com https://bdoph.me/login")
        with self.assertRaises(UrlInputValidationError):
            validate_single_submitted_url("not a url")

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

    def test_unvalidated_tls_and_non_public_dns_are_risk_signals(self):
        intelligence = LinkIntelligence(canonical_host="example.test", dns_public_resolvable=False, tls_certificate_valid=False)
        signals, score = intelligence_risk_signals(intelligence)
        self.assertIn("Destination does not resolve only to public DNS addresses", signals)
        self.assertIn("HTTPS certificate could not be validated server-side", signals)
        self.assertGreaterEqual(score, 75)

    def test_url_model_release_requires_real_evaluation_evidence(self):
        failures = url_release_failures({"version": "verisuri-url-v1", "dataset_validation": {"production_eligible": True}, "test_rows": 100, "evaluation_protocol": {"holdout_digest": "digest"}, "f1": .9, "recall": .9, "precision": .9, "false_positive_rate": .01})
        self.assertEqual(failures, [])
        self.assertTrue(url_release_failures({"version": "verisuri-url-v1"}))

    def test_runtime_model_loader_requires_an_approved_release(self):
        metrics = {"version": "verisuri-url-v1", "model_kind": "url-phishing", "release_status": "approved", "dataset_validation": {"production_eligible": True}}
        self.assertTrue(UrlPhishingModel.approved_metrics(metrics))
        metrics["release_status"] = "candidate"
        self.assertFalse(UrlPhishingModel.approved_metrics(metrics))

    def test_model_only_score_cannot_override_official_or_become_high_risk(self):
        self.assertIsNone(UrlPhishingModel.decision_contribution(99, official_domain=True, corroborated=False))
        self.assertEqual(UrlPhishingModel.decision_contribution(99, official_domain=False, corroborated=False), 59)
        self.assertEqual(UrlPhishingModel.decision_contribution(99, official_domain=False, corroborated=True), 99)

    def test_malformed_url_is_safe_to_reject(self):
        host, canonical = normalize_url("https://[bad-host")
        self.assertEqual((host, canonical), ("", ""))
        signals, score = url_signals("https://[bad-host")
        self.assertEqual(signals, ["The URL has no valid hostname"])
        self.assertEqual(score, 90)


if __name__ == "__main__":
    unittest.main()
