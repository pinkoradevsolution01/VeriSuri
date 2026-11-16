"""Fail a release when V1 metrics do not meet the declared acceptance thresholds."""
import argparse, json
from pathlib import Path

parser = argparse.ArgumentParser(); parser.add_argument("metrics", type=Path); parser.add_argument("--min-f1", type=float, default=.80); parser.add_argument("--min-recall", type=float, default=.85)
args = parser.parse_args(); metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
if metrics["f1"] < args.min_f1 or metrics["recall"] < args.min_recall: raise SystemExit(f"Model release blocked: f1={metrics['f1']}, recall={metrics['recall']}")
print("Model release checks passed")
