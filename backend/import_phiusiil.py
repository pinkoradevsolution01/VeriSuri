"""Prepare the licensed UCI PhiUSIIL URL dataset as a VeriSuri model candidate.

The output is a release candidate only. A named human reviewer must still
approve a model after held-out evaluation; this tool never activates a model.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.url_validation import canonical_url

SOURCE_URL = "https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset"
DATASET_CITATION = "Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website) [Dataset]. UCI Machine Learning Repository."
LICENSE = "CC BY 4.0"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="PhiUSIIL_Phishing_URL_Dataset.csv downloaded from UCI")
    parser.add_argument("--output", type=Path, default=Path("backend/data/approved_urls.csv"))
    parser.add_argument("--provenance", type=Path, default=Path("backend/data/approved_urls.phiusiil.provenance.json"))
    parser.add_argument("--allow-licensed-public-dataset", action="store_true", help="Acknowledge CC BY 4.0 attribution and candidate-only use")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    if not args.allow_licensed_public_dataset:
        raise SystemExit("Use --allow-licensed-public-dataset after reviewing the UCI CC BY 4.0 licence and attribution requirement.")
    if not args.input.is_file():
        raise SystemExit(f"Input dataset not found: {args.input}")
    if args.output.exists() and not args.overwrite:
        raise SystemExit(f"{args.output} already exists. Use --overwrite only if you intend to replace it.")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    valid, skipped = 0, 0
    with args.input.open(encoding="utf-8-sig", newline="") as source, args.output.open("w", encoding="utf-8", newline="") as target:
        reader = csv.DictReader(source)
        if not {"URL", "label"} <= set(reader.fieldnames or []):
            raise SystemExit("The UCI CSV must include URL and label columns.")
        writer = csv.DictWriter(target, fieldnames=["url", "label", "scam_type", "source", "consent_reference", "moderation_reference"])
        writer.writeheader()
        for row in reader:
            try:
                url = canonical_url(row["URL"])
                # UCI documents 0 as phishing and 1 as legitimate. VeriSuri
                # uses 1 as phishing and 0 as legitimate.
                phishing = (row.get("label") or "").strip() == "0"
                if (row.get("label") or "").strip() not in {"0", "1"}:
                    skipped += 1
                    continue
                writer.writerow({
                    "url": url, "label": "1" if phishing else "0",
                    "scam_type": "phishing" if phishing else "legitimate",
                    "source": "UCI PhiUSIIL phishing URL dataset",
                    "consent_reference": "UCI-967-CC-BY-4.0",
                    "moderation_reference": "UCI-967-published-label",
                })
                valid += 1
            except (TypeError, ValueError):
                skipped += 1
    provenance = {
        "source_url": SOURCE_URL, "citation": DATASET_CITATION, "license": LICENSE,
        "retrieved_at": datetime.now(timezone.utc).isoformat(), "input_sha256": sha256(args.input),
        "output_sha256": sha256(args.output), "rows_written": valid, "rows_skipped": skipped,
        "label_mapping": {"UCI 0": "VeriSuri phishing (1)", "UCI 1": "VeriSuri legitimate (0)"},
        "activation_notice": "Candidate only. Evaluate and obtain named human approval before deployment.",
    }
    args.provenance.write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    print(json.dumps(provenance, indent=2))


if __name__ == "__main__":
    main()
