"""Generate fictional development-only records. Never use this output for production evaluation."""
import csv
from itertools import cycle
from pathlib import Path

SCAM = [
    "URGENT: Verify your {brand} account now through {link} to avoid suspension.",
    "Congratulations! Claim your cash prize today. Send your OTP to complete verification.",
    "May problema ang account mo. Click {link} and enter your PIN immediately.",
    "Your parcel is held. Pay a small fee at {link} within one hour.",
    "I am from customer support. Please share the code we sent to secure your account.",
    "Limited offer: receive a refund now by confirming your mobile banking password.",
]
LEGITIMATE = [
    "Salamat sa inyong order. Ipapadala namin ang update through the official app.",
    "Your appointment is confirmed for tomorrow at 10:00 AM.",
    "Reminder: review your transaction history in the official {brand} application.",
    "Hi, your delivery is scheduled today. No payment link is required.",
    "Thank you for contacting support. We will never ask for your OTP or password.",
    "Your monthly statement is available in the secure customer portal.",
]
BRANDS = ["GCash", "Maya", "bank", "wallet"]
LINKS = ["https://verify-demo.example", "https://claim-demo.example"]

def format_message(template: str, index: int) -> str:
    return template.format(brand=BRANDS[index % len(BRANDS)], link=LINKS[index % len(LINKS)])

def main() -> None:
    path = Path("backend/data/synthetic_demo_messages.csv")
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for index in range(60):
        language = ("en", "fil", "taglish")[index % 3]
        rows.append({"text": format_message(SCAM[index % len(SCAM)], index), "label": 1, "language": language, "source": "synthetic-development-only", "consent_reference": "not-for-production"})
        rows.append({"text": format_message(LEGITIMATE[index % len(LEGITIMATE)], index), "label": 0, "language": language, "source": "synthetic-development-only", "consent_reference": "not-for-production"})
    with path.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=rows[0].keys()); writer.writeheader(); writer.writerows(rows)
    print(f"Wrote {len(rows)} synthetic development-only records to {path}")

if __name__ == "__main__": main()
