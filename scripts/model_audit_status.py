"""Show completion status for model-assisted human reviewers."""

from __future__ import annotations

import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
REVIEWERS_DIR = BASE_DIR / "annotations" / "model_audit" / "reviewers"


def main() -> int:
    paths = sorted(REVIEWERS_DIR.glob("reviewer_*.jsonl")) if REVIEWERS_DIR.exists() else []
    print(f"{'Reviewer':<22} {'Progress':<13} {'Percent':>8}  Last saved (UTC)")
    print("-" * 78)
    for path in paths:
        with path.open(encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle if line.strip()]
        completed = sum(row.get("_status") == "completed" for row in rows)
        saved = [row.get("_saved_at_utc") for row in rows if row.get("_saved_at_utc")]
        reviewer = rows[0].get("reviewer", path.stem) if rows else path.stem
        percent = completed / len(rows) * 100 if rows else 0
        print(
            f"{reviewer:<22} {f'{completed}/{len(rows)}':<13} {percent:>7.1f}%  "
            f"{max(saved) if saved else '-'}"
        )
    if not paths:
        print("No formal model-audit reviewer files yet.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
