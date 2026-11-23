"""Approved calibrated URL model. It is absent until a reviewed release exists."""
from __future__ import annotations

import json
from pathlib import Path

import joblib

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "verisuri_url_v1.joblib"
METRICS_PATH = Path(__file__).resolve().parents[2] / "models" / "verisuri_url_v1.metrics.json"


class UrlPhishingModel:
    def __init__(self) -> None:
        self.model = None
        self.version = "url-rules-only"
        self.release_approved = False
        if MODEL_PATH.exists() and METRICS_PATH.exists():
            try:
                metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
                if metrics.get("model_kind") == "url-phishing" and metrics.get("release_status") == "approved" and metrics.get("dataset_validation", {}).get("production_eligible"):
                    self.model = joblib.load(MODEL_PATH)
                    self.version = str(metrics["version"])
                    self.release_approved = True
            except Exception:
                self.model = None

    def predict(self, canonical_url: str) -> int | None:
        if self.model is None:
            return None
        try:
            return round(float(self.model.predict_proba([canonical_url])[0][1]) * 100)
        except Exception:
            return None
