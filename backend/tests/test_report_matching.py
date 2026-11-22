import unittest

from backend.app.services.supabase import SupabaseRepository


class ReportMatchingTests(unittest.TestCase):
    def test_philippine_mobile_formats_share_one_canonical_hash(self):
        first = SupabaseRepository.reported_identifier_hashes("gcash", "0917 123 4567")[0]
        second = SupabaseRepository.reported_identifier_hashes("gcash", "+63 917-123-4567")[0]
        third = SupabaseRepository.reported_identifier_hashes("phone", "9171234567")[0]
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_bank_spacing_and_hyphens_do_not_change_canonical_hash(self):
        first = SupabaseRepository.reported_identifier_hashes("bank", "1234-5678-90")[0]
        second = SupabaseRepository.reported_identifier_hashes("bank", "1234 5678 90")[0]
        self.assertEqual(first, second)

    def test_wallet_phone_aliases_are_checked_together(self):
        self.assertEqual(SupabaseRepository.matching_entity_types("maya"), ["gcash", "maya", "phone"])
        self.assertEqual(SupabaseRepository.matching_entity_types("bank"), ["bank"])

    def test_message_paste_extracts_a_mobile_identifier_for_matching(self):
        message = "Send the payment now to Maya number +63 917-123-4567 to avoid cancellation."
        self.assertEqual(SupabaseRepository.extract_reported_identifier("maya", message), "+63 917-123-4567")

    def test_message_paste_extracts_url_for_report_matching(self):
        message = "Your BDO account needs verification at https://bdoph.example/login?offer=1. Do not delay."
        self.assertEqual(SupabaseRepository.extract_reported_identifier("url", message), "https://bdoph.example/login?offer=1")


if __name__ == "__main__":
    unittest.main()
