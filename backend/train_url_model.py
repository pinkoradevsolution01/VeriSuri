"""Train a calibrated URL phishing model from permissioned, moderated data only."""
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
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from urllib.parse import urlsplit

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.url_validation import load_permissioned_url_rows


def metrics_for(labels: list[int], probabilities: list[float]) -> dict[str, float]:
    predictions = [int(value >= .5) for value in probabilities]
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
    false_positives = sum(predicted == 1 and actual == 0 for actual, predicted in zip(labels, predictions))
    negatives = sum(actual == 0 for actual in labels)
    return {
        "accuracy": round(accuracy_score(labels, predictions), 4), "precision": round(precision, 4),
        "recall": round(recall, 4), "f1": round(f1, 4),
        "false_positive_rate": round(false_positives / negatives, 4) if negatives else 1.0,
        "brier_score": round(brier_score_loss(labels, probabilities), 4),
        "roc_auc": round(roc_auc_score(labels, probabilities), 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path, help="Permissioned CSV: url,label,scam_type,source,consent_reference,moderation_reference")
    parser.add_argument("--output", type=Path, default=Path("backend/models/verisuri_url_v1.joblib"))
    parser.add_argument("--metrics", type=Path, default=Path("backend/models/verisuri_url_v1.metrics.json"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--minimum-rows", type=int, default=500)
    args = parser.parse_args()
    if "demo" in args.version.casefold() or "synthetic" in args.version.casefold():
        raise ValueError("Demo and synthetic versions cannot be URL-model release candidates.")
    if not args.dataset.is_file():
        raise SystemExit(
            f"Dataset not found: {args.dataset}. Copy backend/data/permissioned_urls.template.csv.example "
            "to backend/data/approved_urls.csv, replace every example row with permissioned reviewed URLs, then rerun."
        )
    rows, validation = load_permissioned_url_rows(args.dataset, minimum_rows=args.minimum_rows)
    urls, labels = [row["url"] for row in rows], [int(row["label"]) for row in rows]
    groups = [urlsplit(url).hostname or url for url in urls]
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    train_indexes, test_indexes = next(splitter.split(urls, labels, groups))
    train_x, test_x = [urls[index] for index in train_indexes], [urls[index] for index in test_indexes]
    train_y, test_y = [labels[index] for index in train_indexes], [labels[index] for index in test_indexes]
    model = CalibratedClassifierCV(
        Pipeline([("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)), ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42))]),
        method="sigmoid", cv=3,
    )
    model.fit(train_x, train_y)
    probabilities = model.predict_proba(test_x)[:, 1].tolist()
    holdout = [hashlib.sha256(value.encode("utf-8")).hexdigest() for value in test_x]
    metrics = {
        "version": args.version, "model_kind": "url-phishing", "release_status": "candidate",
        "dataset_rows": len(rows), "train_rows": len(train_x), "test_rows": len(test_x),
        **metrics_for(test_y, probabilities), "dataset_validation": validation,
        "evaluation_protocol": {
            "holdout": "Stratified group holdout by hostname; no hostname appears in both training and test partitions.",
            "holdout_digest": hashlib.sha256("\n".join(sorted(holdout)).encode("utf-8")).hexdigest(),
            "calibration": "Sigmoid calibration with three folds fitted only on the training partition.",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output)
    args.metrics.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
