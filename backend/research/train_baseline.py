"""Train a clearly non-production research baseline from licensed data.

This deliberately cannot register or release a VeriSuri production model.
"""
from __future__ import annotations
import argparse, csv, json
from collections import Counter
from pathlib import Path
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

REQUIRED = {"text", "label", "language", "source", "source_url", "license", "translation_type", "source_text"}
TRANSLATIONS = {"original", "human_translation", "machine_translation"}

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    with args.dataset.open(encoding="utf-8", newline="") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or not REQUIRED.issubset(reader.fieldnames):
            raise ValueError(f"Research CSV requires: {', '.join(sorted(REQUIRED))}")
        rows = list(reader)
    if len(rows) < 100 or {row["label"] for row in rows} != {"0", "1"}:
        raise ValueError("Use 100+ licensed research examples with both labels.")
    for line, row in enumerate(rows, start=2):
        if not row["text"].strip() or not row["source_url"].startswith("https://") or not row["license"].strip():
            raise ValueError(f"Row {line} is missing a licensed source record.")
        if row["translation_type"] not in TRANSLATIONS:
            raise ValueError(f"Row {line} has an invalid translation_type.")
    model = Pipeline([("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=1)), ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced"))])
    model.fit([row["text"] for row in rows], [int(row["label"]) for row in rows])
    output = Path(__file__).resolve().parent / "output"; output.mkdir(exist_ok=True)
    joblib.dump(model, output / f"{args.version}.joblib")
    metrics = {"version": args.version, "release_status": "research_only", "production_eligible": False, "rows": len(rows), "languages": dict(Counter(row["language"] for row in rows)), "translation_types": dict(Counter(row["translation_type"] for row in rows)), "notice": "Synthetic translations and international research data cannot be registered as a production VeriSuri model."}
    (output / f"{args.version}.metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__": main()
