"""Privacy-preserving quality checks for permissioned model datasets."""
from __future__ import annotations

import csv
import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any

REQUIRED_COLUMNS = {"text", "label", "language", "source", "consent_reference"}
SUPPORTED_LANGUAGES = {"en", "fil", "taglish"}


class DatasetValidationError(ValueError):
    pass


def _fingerprint(text: str) -> str:
    normalized = re.sub(r"\s+", " ", text.strip().casefold())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_permissioned_rows(
    dataset: Path,
    *,
    minimum_rows: int = 300,
    minimum_per_language: int = 60,
    minimum_per_class_language: int = 20,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Load only non-synthetic, explicitly consented rows without logging text."""
    with dataset.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        columns = set(reader.fieldnames or [])
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise DatasetValidationError(f"Dataset is missing required columns: {', '.join(sorted(missing))}.")
        rows = list(reader)

    clean: list[dict[str, str]] = []
    fingerprints: set[str] = set()
    language_counts: Counter[str] = Counter()
    class_language_counts: Counter[tuple[str, str]] = Counter()
    for line, row in enumerate(rows, start=2):
        text = (row.get("text") or "").strip()
        label = (row.get("label") or "").strip()
        language = (row.get("language") or "").strip().lower()
        source_name = (row.get("source") or "").strip()
        consent = (row.get("consent_reference") or "").strip()
        if len(text) < 6:
            raise DatasetValidationError(f"Row {line} has no usable message text.")
        if label not in {"0", "1"}:
            raise DatasetValidationError(f"Row {line} has an invalid label; use 0 or 1.")
        if language not in SUPPORTED_LANGUAGES:
            raise DatasetValidationError(f"Row {line} has unsupported language '{language}'.")
        if len(source_name) < 3 or len(consent) < 3:
            raise DatasetValidationError(f"Row {line} is missing a usable source or consent reference.")
        if "synthetic" in source_name.casefold() or consent.casefold() in {"demo", "not-for-production"}:
            raise DatasetValidationError("Synthetic or demo records cannot be used for a release candidate.")
        fingerprint = _fingerprint(text)
        if fingerprint in fingerprints:
            raise DatasetValidationError(f"Row {line} duplicates an earlier message. Remove duplicate records before training.")
        fingerprints.add(fingerprint)
        clean.append({"text": text, "label": label, "language": language, "source": source_name, "consent_reference": consent})
        language_counts[language] += 1
        class_language_counts[(language, label)] += 1

    if len(clean) < minimum_rows:
        raise DatasetValidationError(f"Use at least {minimum_rows} permissioned, labelled messages; received {len(clean)}.")
    if {row["label"] for row in clean} != {"0", "1"}:
        raise DatasetValidationError("The dataset must contain both scam (1) and legitimate (0) messages.")
    for language in sorted(SUPPORTED_LANGUAGES):
        if language_counts[language] < minimum_per_language:
            raise DatasetValidationError(f"Need at least {minimum_per_language} {language} examples; received {language_counts[language]}.")
        for label in ("0", "1"):
            count = class_language_counts[(language, label)]
            if count < minimum_per_class_language:
                raise DatasetValidationError(f"Need at least {minimum_per_class_language} {language} examples with label {label}; received {count}.")

    return clean, {
        "production_eligible": True,
        "row_count": len(clean),
        "language_counts": dict(sorted(language_counts.items())),
        "class_language_counts": {f"{language}:{label}": count for (language, label), count in sorted(class_language_counts.items())},
        "dataset_digest": hashlib.sha256("\n".join(sorted(fingerprints)).encode("utf-8")).hexdigest(),
        "privacy_note": "Only aggregate counts and irreversible message fingerprints are stored in this report.",
    }
