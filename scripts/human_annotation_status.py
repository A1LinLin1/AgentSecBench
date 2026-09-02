"""Show completion status for separately stored human annotators."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
ANNOTATOR_DIR = BASE_DIR / "annotations" / "annotator"


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    paths = sorted(ANNOTATOR_DIR.glob("annotator_*.jsonl"))
    participants = ANNOTATOR_DIR / "participants"
    if participants.exists():
        paths.extend(sorted(participants.glob("annotator_*.jsonl")))
    status = []
    for path in paths:
        rows = read_jsonl(path)
        completed = sum(row.get("_status") == "completed" for row in rows)
        saved = [row.get("_saved_at_utc") for row in rows if row.get("_saved_at_utc")]
        status.append(
            {
                "annotator": rows[0].get("annotator", path.stem) if rows else path.stem,
                "completed": completed,
                "total": len(rows),
                "percent": round(completed / len(rows) * 100, 1) if rows else 0.0,
                "last_saved_utc": max(saved) if saved else None,
                "file": path.relative_to(BASE_DIR).as_posix(),
            }
        )
    if args.json:
        print(json.dumps(status, ensure_ascii=False, indent=2))
    else:
        print(f"{'Annotator':<22} {'Progress':<13} {'Percent':>8}  Last saved (UTC)")
        print("-" * 78)
        for row in status:
            progress = f"{row['completed']}/{row['total']}"
            print(
                f"{row['annotator']:<22} {progress:<13} {row['percent']:>7.1f}%  "
                f"{row['last_saved_utc'] or '-'}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
