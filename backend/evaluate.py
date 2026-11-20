"""Block model releases that lack multilingual, held-out validation evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def release_failures(metrics: dict, *, min_f1: float, min_recall: float, min_precision: float, max_false_positive_rate: float) -> list[str]:
    failures: list[str] = []
    if "demo" in str(metrics.get("version", "")).casefold() or "synthetic" in str(metrics.get("version", "")).casefold():
        failures.append("demo or synthetic model versions cannot be released")
    if not metrics.get("dataset_validation", {}).get("production_eligible"):
        failures.append("dataset permission and diversity validation is missing or failed")
    if metrics.get("test_rows", 0) < 60:
        failures.append("held-out test set must contain at least 60 records")
    if not metrics.get("evaluation_protocol", {}).get("holdout_digest"):
        failures.append("held-out evaluation evidence is missing")
    scopes = {"overall": metrics, **metrics.get("by_language", {})}
    for scope, result in scopes.items():
        if scope != "overall" and result.get("test_rows", 0) < 10:
            failures.append(f"{scope} has fewer than 10 held-out test records")
            continue
        if result.get("f1", 0) < min_f1:
            failures.append(f"{scope} F1 is below {min_f1}")
        if result.get("recall", 0) < min_recall:
            failures.append(f"{scope} recall is below {min_recall}")
        if result.get("precision", 0) < min_precision:
            failures.append(f"{scope} precision is below {min_precision}")
        if result.get("false_positive_rate", 1) > max_false_positive_rate:
            failures.append(f"{scope} false-positive rate exceeds {max_false_positive_rate}")
    scam_type_results = metrics.get("by_scam_type", {})
    if not scam_type_results:
        failures.append("per-scam-type held-out evaluation is missing")
    for scam_type, result in scam_type_results.items():
        if result.get("scam_test_rows", 0) < 10:
            failures.append(f"{scam_type} has fewer than 10 held-out scam records")
            continue
        if result.get("recall", 0) < min_recall:
            failures.append(f"{scam_type} recall is below {min_recall}")
        if result.get("precision", 0) < min_precision:
            failures.append(f"{scam_type} precision is below {min_precision}")
        if result.get("false_positive_rate", 1) > max_false_positive_rate:
            failures.append(f"{scam_type} false-positive rate exceeds {max_false_positive_rate}")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("metrics", type=Path)
    parser.add_argument("--min-f1", type=float, default=.80)
    parser.add_argument("--min-recall", type=float, default=.85)
    parser.add_argument("--min-precision", type=float, default=.80)
    parser.add_argument("--max-false-positive-rate", type=float, default=.10)
    args = parser.parse_args()
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    failures = release_failures(metrics, min_f1=args.min_f1, min_recall=args.min_recall, min_precision=args.min_precision, max_false_positive_rate=args.max_false_positive_rate)
    if failures:
        raise SystemExit("Model release blocked: " + "; ".join(failures))
    print("Model release checks passed")


if __name__ == "__main__":
    main()
