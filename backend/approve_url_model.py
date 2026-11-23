"""Approve a URL-model release only after automatic quality gates and human review."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from backend.url_validation import url_release_failures


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("metrics", type=Path)
    parser.add_argument("--reviewer", required=True)
    args = parser.parse_args()
    metrics = json.loads(args.metrics.read_text(encoding="utf-8"))
    failures = url_release_failures(metrics)
    if failures:
        raise SystemExit("Approval blocked: " + "; ".join(failures))
    metrics.update({"release_status": "approved", "approved_by": args.reviewer, "approved_at": datetime.now(timezone.utc).isoformat()})
    args.metrics.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(f"Approved {metrics['version']}")


if __name__ == "__main__":
    main()
