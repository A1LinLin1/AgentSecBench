"""Show case-level review progress."""

from __future__ import annotations

import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
RESULT_DIR = BASE_DIR / "analysis" / "case_review" / "reviews"


def main() -> int:
    print(f"{'Reviewer':<24} {'Progress':<12} {'Percent':>8}  Last saved (UTC)")
    print("-" * 78)
    for path in sorted(RESULT_DIR.glob("reviewer_*.jsonl")) if RESULT_DIR.exists() else []:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        completed = [row for row in rows if row.get("_status") == "completed"]
        last = max((row.get("_saved_at_utc", "") for row in rows), default="") or "-"
        reviewer = path.stem.removeprefix("reviewer_")
        percent = len(completed) / len(rows) * 100 if rows else 0
        print(f"{reviewer:<24} {f'{len(completed)}/{len(rows)}':<12} {percent:>7.1f}%  {last}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
