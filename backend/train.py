"""Train VeriSuri only from sufficiently large, permissioned multilingual data."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, brier_score_loss, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.validation import load_permissioned_rows


def metrics_for(labels: list[int], probabilities: list[float]) -> dict[str, float]:
    predictions = [int(value >= .5) for value in probabilities]
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
    false_positives = sum(predicted == 1 and actual == 0 for actual, predicted in zip(labels, predictions))
    negatives = sum(actual == 0 for actual in labels)
    return {
        "accuracy": round(accuracy_score(labels, predictions), 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positives / negatives, 4) if negatives else 1.0,
        "brier_score": round(brier_score_loss(labels, probabilities), 4),
        "roc_auc": round(roc_auc_score(labels, probabilities), 4) if len(set(labels)) == 2 else 0.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path, help="Permissioned CSV with text,label,language,source,consent_reference")
    parser.add_argument("--output", type=Path, default=Path("backend/models/verisuri_v1.joblib"))
    parser.add_argument("--metrics", type=Path, default=Path("backend/models/verisuri_v1.metrics.json"))
    parser.add_argument("--version", required=True, help="A reviewed release-candidate version, never a demo version")
    parser.add_argument("--minimum-rows", type=int, default=300)
    args = parser.parse_args()
    if "demo" in args.version.casefold() or "synthetic" in args.version.casefold():
        raise ValueError("Demo and synthetic versions cannot be trained as release candidates.")

    rows, validation = load_permissioned_rows(args.dataset, minimum_rows=args.minimum_rows)
    texts = [row["text"] for row in rows]
    labels = [int(row["label"]) for row in rows]
    strata = [f"{row['language']}:{row['label']}" for row in rows]
    train_x, test_x, train_y, test_y, train_rows, test_rows = train_test_split(texts, labels, rows, test_size=.2, random_state=42, stratify=strata)
    base = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)),
    ])
    model = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    model.fit(train_x, train_y)
    probabilities = model.predict_proba(test_x)[:, 1].tolist()
    by_language: dict[str, dict[str, float | int]] = {}
    for language in ("en", "fil", "taglish"):
        positions = [index for index, row in enumerate(test_rows) if row["language"] == language]
        by_language[language] = {"test_rows": len(positions), **metrics_for([test_y[index] for index in positions], [probabilities[index] for index in positions])}
    holdout_hashes = [hashlib.sha256(row["text"].strip().casefold().encode("utf-8")).hexdigest() for row in test_rows]
    metrics = {
        "version": args.version,
        "release_status": "candidate",
        "dataset_rows": len(rows),
        "train_rows": len(train_rows),
        "test_rows": len(test_rows),
        **metrics_for(test_y, probabilities),
        "by_language": by_language,
        "dataset_validation": validation,
        "evaluation_protocol": {
            "holdout": "Stratified 20% holdout by language and label; no holdout text is stored in model metadata.",
            "holdout_digest": hashlib.sha256("\n".join(sorted(holdout_hashes)).encode("utf-8")).hexdigest(),
            "calibration": "Sigmoid calibration with three folds fitted on the training partition only.",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output)
    args.metrics.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
