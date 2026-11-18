"""Record a human-reviewed release approval only after automated gates pass."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.evaluate import release_failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("metrics", type=Path)
    parser.add_argument("--reviewer", required=True, help="Accountable reviewer identifier; do not use a secret")
    args = parser.parse_args()
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    failures = release_failures(metrics, min_f1=.80, min_recall=.85, min_precision=.80, max_false_positive_rate=.10)
    if failures:
        raise SystemExit("Approval blocked: " + "; ".join(failures))
    metrics["release_status"] = "approved"
    metrics["approved_by"] = args.reviewer
    metrics["approved_at"] = datetime.now(timezone.utc).isoformat()
    args.metrics.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Approved {metrics['version']}")


if __name__ == "__main__":
    main()
