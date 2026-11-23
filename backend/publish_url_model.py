"""Publish a human-approved URL model to private Supabase Storage.

Run this only from a trusted developer machine after `approve_url_model` succeeds.
It deliberately uses the service-role key only on the server/developer side and
creates a non-public Storage bucket.  No artifact or credential is committed.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

from backend.app.config import get_settings
from backend.url_validation import url_release_failures

MODEL_PATH = Path("backend/models/verisuri_url_v1.joblib")
METRICS_PATH = Path("backend/models/verisuri_url_v1.metrics.json")


def _headers(key: str, content_type: str | None = None) -> dict[str, str]:
    headers = {"apikey": key, "Authorization": f"Bearer {key}"}
    if content_type:
        headers["Content-Type"] = content_type
    return headers


def main() -> None:
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_role_key:
        raise SystemExit("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required to publish a private model artifact.")
    if not MODEL_PATH.exists() or not METRICS_PATH.exists():
        raise SystemExit("Train and approve the local URL model before publishing it.")

    artifact = MODEL_PATH.read_bytes()
    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    failures = url_release_failures(metrics)
    if metrics.get("model_kind") != "url-phishing" or metrics.get("release_status") != "approved" or failures:
        raise SystemExit("Publish blocked: the URL model must be human-approved and pass all release checks. " + "; ".join(failures))

    metrics.update({
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "artifact_size_bytes": len(artifact),
        "artifact_published_at": datetime.now(timezone.utc).isoformat(),
    })
    # Retain the private integrity metadata locally too; .gitignore prevents it
    # from ever becoming a repository artifact.
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    base = settings.supabase_url.rstrip("/")
    bucket = settings.url_model_bucket
    key = settings.supabase_service_role_key
    stage = "create private bucket"
    try:
        with httpx.Client(timeout=httpx.Timeout(120.0, connect=10.0)) as client:
            created = client.post(
                f"{base}/storage/v1/bucket",
                headers=_headers(key, "application/json"),
                json={"id": bucket, "name": bucket, "public": False},
            )
            # Supabase Storage returns either 400 or 409 for an already-created
            # bucket depending on the platform version. The following read is
            # the authoritative check, including its non-public setting.
            if created.status_code not in {200, 201, 400, 409}:
                created.raise_for_status()
            stage = "verify private bucket"
            bucket_response = client.get(f"{base}/storage/v1/bucket/{bucket}", headers=_headers(key))
            bucket_response.raise_for_status()
            if bool(bucket_response.json().get("public")):
                raise SystemExit("Publish blocked: the model bucket must remain private.")
            for path, body, content_type in (
                (settings.url_model_metrics_path, json.dumps(metrics, indent=2).encode("utf-8"), "application/json"),
                (settings.url_model_artifact_path, artifact, "application/octet-stream"),
            ):
                stage = f"upload {'metadata' if content_type == 'application/json' else 'model artifact'}"
                uploaded = client.post(
                    f"{base}/storage/v1/object/{bucket}/{path}",
                    headers={**_headers(key, content_type), "x-upsert": "true"},
                    content=body,
                )
                uploaded.raise_for_status()
    except httpx.HTTPStatusError as error:
        # Deliberately expose only the HTTP status, never response bodies or
        # request headers, because those can contain sensitive project detail.
        raise SystemExit(
            f"Private model publication failed during {stage} with HTTP {error.response.status_code}. "
            "Check the Supabase Storage bucket settings and service-role key."
        ) from error
    except httpx.HTTPError as error:
        raise SystemExit("Private model publication could not reach Supabase Storage.") from error

    print(json.dumps({
        "published": True,
        "bucket": bucket,
        "artifact_path": settings.url_model_artifact_path,
        "metrics_path": settings.url_model_metrics_path,
        "sha256": metrics["artifact_sha256"],
        "bytes": metrics["artifact_size_bytes"],
    }, indent=2))


if __name__ == "__main__":
    main()
