import csv
import tempfile
import unittest
from pathlib import Path

from backend.app.services.detector import build_assessment
from backend.validation import DatasetValidationError, load_permissioned_rows


class SafetyPolicyTests(unittest.TestCase):
    def test_unknown_result_remains_cautionary(self):
        result = build_assessment(0, [], "verisuri-rules-v1", "rule-engine", "message")
        self.assertEqual(result.level.value, "medium")
        self.assertIn("Use caution", result.verdict)
        self.assertEqual(result.evidence_confidence, "limited")
        self.assertTrue(result.verification_required)

    def test_confirmed_report_match_is_high_confidence_evidence(self):
        result = build_assessment(80, ["Matched 2 confirmed community report(s)"], "verisuri-rules-v1", "supabase-report-matching", "report")
        self.assertEqual(result.evidence_confidence, "high")
        self.assertIn("High-confidence", result.verdict)

    def test_training_row_requires_moderation_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "candidate.csv"
            with path.open("w", encoding="utf-8", newline="") as source:
                writer = csv.DictWriter(source, fieldnames=["text", "label", "language", "scam_type", "source", "consent_reference", "moderation_reference"])
                writer.writeheader()
                writer.writerow({"text": "This is a sufficiently long legitimate notice", "label": "0", "language": "en", "scam_type": "legitimate", "source": "permissioned", "consent_reference": "consent-1", "moderation_reference": ""})
            with self.assertRaises(DatasetValidationError):
                load_permissioned_rows(path, minimum_rows=1, minimum_per_language=0, minimum_per_class_language=0, minimum_per_scam_type=0)


if __name__ == "__main__":
    unittest.main()
