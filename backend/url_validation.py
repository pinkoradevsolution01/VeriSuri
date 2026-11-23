"""Permission, quality, and release gates for VeriSuri URL-model datasets."""
from __future__ import annotations

import csv
import hashlib
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

REQUIRED_COLUMNS = {"url", "label", "scam_type", "source", "consent_reference", "moderation_reference"}


class UrlDatasetValidationError(ValueError):
    pass


def canonical_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UrlDatasetValidationError("Each URL must use HTTP or HTTPS and include a hostname.")
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{parsed.path or '/'}" + (f"?{parsed.query}" if parsed.query else "")


def load_permissioned_url_rows(dataset: Path, *, minimum_rows: int = 500, minimum_per_class: int = 150) -> tuple[list[dict[str, str]], dict]:
    with dataset.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
        if missing:
            raise UrlDatasetValidationError(f"Dataset is missing required columns: {', '.join(sorted(missing))}.")
        rows = list(reader)
    clean: list[dict[str, str]] = []
    fingerprints: set[str] = set()
    counts: Counter[str] = Counter()
    for line, row in enumerate(rows, start=2):
        url = canonical_url(row.get("url") or "")
        label = (row.get("label") or "").strip()
        scam_type = (row.get("scam_type") or "").strip().casefold()
        source_name = (row.get("source") or "").strip()
        consent = (row.get("consent_reference") or "").strip()
        moderation = (row.get("moderation_reference") or "").strip()
        if label not in {"0", "1"}:
            raise UrlDatasetValidationError(f"Row {line} has an invalid label; use 0 or 1.")
        if label == "0" and scam_type != "legitimate":
            raise UrlDatasetValidationError(f"Row {line} is legitimate and must use scam_type 'legitimate'.")
        if label == "1" and scam_type != "phishing":
            raise UrlDatasetValidationError(f"Row {line} is a phishing URL and must use scam_type 'phishing'.")
        if min(len(source_name), len(consent), len(moderation)) < 3:
            raise UrlDatasetValidationError(f"Row {line} is missing source, consent, or moderation evidence.")
        if "synthetic" in source_name.casefold() or consent.casefold() in {"demo", "not-for-production"}:
            raise UrlDatasetValidationError("Synthetic or demo URL records cannot be used for a release candidate.")
        fingerprint = hashlib.sha256(url.encode("utf-8")).hexdigest()
        if fingerprint in fingerprints:
            raise UrlDatasetValidationError(f"Row {line} duplicates an earlier URL.")
        fingerprints.add(fingerprint)
        clean.append({"url": url, "label": label, "scam_type": scam_type, "source": source_name, "consent_reference": consent, "moderation_reference": moderation})
        counts[label] += 1
    if len(clean) < minimum_rows:
        raise UrlDatasetValidationError(f"Use at least {minimum_rows} permissioned labelled URLs; received {len(clean)}.")
    if set(counts) != {"0", "1"} or min(counts.values()) < minimum_per_class:
        raise UrlDatasetValidationError(f"Need at least {minimum_per_class} phishing and legitimate URLs.")
    return clean, {
        "production_eligible": True, "row_count": len(clean), "class_counts": dict(counts),
        "dataset_digest": hashlib.sha256("\n".join(sorted(fingerprints)).encode("utf-8")).hexdigest(),
        "privacy_note": "Only aggregate counts and irreversible URL fingerprints are retained in release metadata.",
    }


def url_release_failures(metrics: dict, *, min_f1: float = .80, min_recall: float = .85, min_precision: float = .80, max_false_positive_rate: float = .10) -> list[str]:
    failures: list[str] = []
    if "demo" in str(metrics.get("version", "")).casefold() or "synthetic" in str(metrics.get("version", "")).casefold():
        failures.append("demo or synthetic URL model versions cannot be released")
    if not metrics.get("dataset_validation", {}).get("production_eligible"):
        failures.append("dataset permission and quality validation is missing or failed")
    if metrics.get("test_rows", 0) < 100:
        failures.append("held-out URL test set must contain at least 100 records")
    if not metrics.get("evaluation_protocol", {}).get("holdout_digest"):
        failures.append("held-out URL evaluation evidence is missing")
    for key, threshold, label in (("f1", min_f1, "F1"), ("recall", min_recall, "recall"), ("precision", min_precision, "precision")):
        if metrics.get(key, 0) < threshold:
            failures.append(f"URL model {label} is below {threshold}")
    if metrics.get("false_positive_rate", 1) > max_false_positive_rate:
        failures.append(f"URL model false-positive rate exceeds {max_false_positive_rate}")
    return failures
