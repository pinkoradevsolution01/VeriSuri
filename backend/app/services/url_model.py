"""Load an approved calibrated URL model without exposing it to browsers."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import tempfile

import httpx
import joblib

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "verisuri_url_v1.joblib"
METRICS_PATH = Path(__file__).resolve().parents[2] / "models" / "verisuri_url_v1.metrics.json"


class UrlPhishingModel:
    def __init__(self) -> None:
        self.model = None
        self.version = "url-rules-only"
        self.release_approved = False
        self._load_lock = asyncio.Lock()
        if MODEL_PATH.exists() and METRICS_PATH.exists():
            try:
                metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
                self._load(MODEL_PATH, metrics)
            except Exception:
                self.model = None

    @staticmethod
    def approved_metrics(metrics: dict) -> bool:
        """Require the same explicit human approval and dataset gates in every runtime."""
        return bool(
            metrics.get("model_kind") == "url-phishing"
            and metrics.get("release_status") == "approved"
            and metrics.get("dataset_validation", {}).get("production_eligible")
            and str(metrics.get("version") or "").strip()
        )

    @staticmethod
    def remote_configured(supabase_url: str | None, service_role_key: str | None) -> bool:
        return bool(supabase_url and service_role_key)

    def _load(self, artifact_path: Path, metrics: dict) -> bool:
        if not self.approved_metrics(metrics):
            return False
        self.model = joblib.load(artifact_path)
        self.version = str(metrics["version"])
        self.release_approved = True
        return True

    async def ensure_loaded(
        self,
        *,
        supabase_url: str | None,
        service_role_key: str | None,
        bucket: str,
        artifact_path: str,
        metrics_path: str,
    ) -> bool:
        """Fetch a signed-off model from private Storage into the server's temp cache.

        The service-role credential stays within the API function.  A SHA-256 in
        the reviewed metadata prevents accepting a partial or substituted model.
        If Storage is unavailable, rules and threat feeds remain available.
        """
        if self.model is not None:
            return True
        if not self.remote_configured(supabase_url, service_role_key):
            return False
        async with self._load_lock:
            if self.model is not None:
                return True
            headers = {"apikey": service_role_key or "", "Authorization": f"Bearer {service_role_key or ''}"}
            base = (supabase_url or "").rstrip("/")
            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(55.0, connect=10.0)) as client:
                    metrics_response = await client.get(
                        f"{base}/storage/v1/object/{bucket}/{metrics_path}", headers=headers
                    )
                    metrics_response.raise_for_status()
                    metrics = metrics_response.json()
                    if not isinstance(metrics, dict) or not self.approved_metrics(metrics):
                        return False
                    expected_sha = str(metrics.get("artifact_sha256") or "")
                    if len(expected_sha) != 64:
                        return False
                    artifact_response = await client.get(
                        f"{base}/storage/v1/object/{bucket}/{artifact_path}", headers=headers
                    )
                    artifact_response.raise_for_status()
                    artifact = artifact_response.content
                if hashlib.sha256(artifact).hexdigest() != expected_sha:
                    return False
                cache_dir = Path(tempfile.gettempdir()) / "verisuri-models"
                cache_dir.mkdir(parents=True, exist_ok=True)
                cache_path = cache_dir / f"{expected_sha}.joblib"
                temporary_path = cache_dir / f"{expected_sha}.part"
                temporary_path.write_bytes(artifact)
                os.replace(temporary_path, cache_path)
                return self._load(cache_path, metrics)
            except (httpx.HTTPError, OSError, ValueError, TypeError, json.JSONDecodeError):
                return False

    def predict(self, canonical_url: str) -> int | None:
        if self.model is None:
            return None
        try:
            return round(float(self.model.predict_proba([canonical_url])[0][1]) * 100)
        except Exception:
            return None

    @staticmethod
    def decision_contribution(probability: int | None, *, official_domain: bool, corroborated: bool) -> int | None:
        """Keep ML screening subordinate to independently verifiable evidence.

        The URL corpus is useful for prioritising review, but a model output alone
        must not label a link as high-risk. A verified-provider domain also cannot
        be overridden by character-pattern ML alone. Confirmed reports and threat
        feed evidence retain their stronger, independently sourced weighting.
        """
        if probability is None or official_domain:
            return None
        if corroborated:
            return probability
        return min(60, round(probability * 0.60))
