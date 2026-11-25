import unittest

from pydantic import ValidationError

from backend.app.schemas import PaymentRequest


class RequestValidationTests(unittest.TestCase):
    def test_payment_wallet_requires_a_philippine_mobile_number(self):
        with self.assertRaises(ValidationError):
            PaymentRequest(identifier="abc", provider="gcash")
        accepted = PaymentRequest(identifier="+63 917-123-4567", provider="gcash")
        self.assertEqual(accepted.provider, "gcash")

    def test_bank_requires_a_plausible_account_number(self):
        with self.assertRaises(ValidationError):
            PaymentRequest(identifier="account name", provider="bank")
        self.assertEqual(PaymentRequest(identifier="1234 5678", provider="bank").provider, "bank")


if __name__ == "__main__":
    unittest.main()
