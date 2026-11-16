from pathlib import Path
import joblib
from backend.app.schemas import Assessment, RiskLevel
from backend.app.services.rules import message_signals

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "verisuri_v1.joblib"

class HybridDetector:
    """Local character-TF-IDF model combined with transparent fraud rules."""
    version = "verisuri-hybrid-v1"
    def __init__(self) -> None:
        self.model = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None
    def analyze(self, text: str) -> Assessment:
        signals, rule_score = message_signals(text)
        model_score = None
        if self.model is not None:
            model_score = round(float(self.model.predict_proba([text])[0][1]) * 100)
            signals.append("Custom VeriSuri text model completed a local assessment")
        score = round(model_score * .65 + rule_score * .35) if model_score is not None else rule_score
        return build_assessment(score, signals, self.version, "hybrid-model" if model_score is not None else "rule-engine", "message", text)

def _brand_name(target: str | None) -> str | None:
    if not target:
        return None
    value = target.lower()
    brands = {"gcash": "GCash", "maya": "Maya", "bdo": "BDO", "bpi": "BPI", "metrobank": "Metrobank", "unionbank": "UnionBank"}
    return next((name for term, name in brands.items() if term in value), None)


def _recommendations(score: int, context: str, target: str | None) -> tuple[str, list[str]]:
    brand = _brand_name(target)
    if context == "link":
        if score >= 30:
            brand_line = f"Do not enter {brand} credentials, OTPs, PINs, or card details." if brand else "Do not enter credentials, OTPs, PINs, or card details."
            official_line = f"Verify any offer only in the official {brand} app or by typing its official website yourself." if brand else "Verify any offer only through the organisation's official app or website that you type yourself."
            return "Treat this link as unsafe.", ["Do not open the link or submit information through it.", brand_line, official_line]
        return "Continue carefully with this link.", ["Do not provide credentials, OTPs, or payment details through an unfamiliar link.", "Independently confirm the sender and destination using an official app or website.", "Stop immediately if the page asks for secrets or urgent payment."]
    if context == "message":
        if score >= 30:
            return "Treat this message as suspicious.", ["Do not reply, click links, or send money because of this message.", "Never share passwords, OTPs, PINs, or card details.", "Verify the claim through the organisation's official app, website, or known phone number."]
        return "Continue carefully with this message.", ["Verify unexpected requests through an official channel before acting.", "Never share passwords, OTPs, PINs, or card details in response to a message.", "Check every included link separately before opening it."]
    if context == "payment":
        if score >= 30:
            return "Do not send money yet.", ["Pause this payment while you verify the recipient independently.", "Contact the person or business through a known official channel, not the contact details in the request.", "Never share OTPs, PINs, passwords, or card details to complete a payment."]
        return "No confirmed report was found—verify before paying.", ["Confirm the recipient's identity using an independent, known contact method.", "Review the account name in the official payment app before sending money.", "Never disclose OTPs, PINs, passwords, or card details."]
    if context == "report":
        if score >= 30:
            return "Treat this reported identifier as unsafe.", ["Do not send money or continue the transaction.", "Keep screenshots and transaction details if you need to report the incident.", "Verify through an official provider channel before taking any further action."]
        return "No confirmed community report was found.", ["A no-match result is not a guarantee that the identifier is safe.", "Verify the person or business independently before sending money.", "Report suspicious activity so it can be reviewed by a moderator."]
    return "Use caution and verify independently.", ["Do not share sensitive information.", "Use official channels to verify unexpected requests.", "Stop if you are pressured to act urgently."]


def build_assessment(score: int, signals: list[str], version: str, source: str, context: str = "general", target: str | None = None) -> Assessment:
    recommendation_title, recommendations = _recommendations(score, context, target)
    if score >= 65: return Assessment(score=score, level=RiskLevel.high, verdict="High risk detected", summary="Do not send money or share credentials until independently verified.", signals=signals, recommendation_title=recommendation_title, recommendations=recommendations, engine_version=version, source=source)
    if score >= 30: return Assessment(score=score, level=RiskLevel.medium, verdict="Use caution", summary="Some scam indicators were found. Verify using an official app or number.", signals=signals, recommendation_title=recommendation_title, recommendations=recommendations, engine_version=version, source=source)
    return Assessment(score=score, level=RiskLevel.low, verdict="No strong scam signal found", summary="No strong indicators were found. Continue to verify unfamiliar payment requests.", signals=signals, recommendation_title=recommendation_title, recommendations=recommendations, engine_version=version, source=source)
