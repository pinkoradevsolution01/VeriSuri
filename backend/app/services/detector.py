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
        return build_assessment(score, signals, self.version, "hybrid-model" if model_score is not None else "rule-engine")

def build_assessment(score: int, signals: list[str], version: str, source: str) -> Assessment:
    if score >= 65: return Assessment(score=score, level=RiskLevel.high, verdict="High risk detected", summary="Do not send money or share credentials until independently verified.", signals=signals, engine_version=version, source=source)
    if score >= 30: return Assessment(score=score, level=RiskLevel.medium, verdict="Use caution", summary="Some scam indicators were found. Verify using an official app or number.", signals=signals, engine_version=version, source=source)
    return Assessment(score=score, level=RiskLevel.low, verdict="No strong scam signal found", summary="No strong indicators were found. Continue to verify unfamiliar payment requests.", signals=signals, engine_version=version, source=source)
