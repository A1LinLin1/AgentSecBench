"""Validate and combine development baseline predictions without reading labels."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUTS = (
    BASE_DIR / "analysis" / "baselines" / "development" / "semgrep_predictions.jsonl",
    BASE_DIR / "analysis" / "baselines" / "development" / "codeql_predictions.jsonl",
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append")
    parser.add_argument("--tasks", type=Path, default=BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl")
    parser.add_argument("--output", type=Path, default=BASE_DIR / "analysis" / "baselines" / "development" / "method_predictions.jsonl")
    args = parser.parse_args()
    inputs = args.input or list(DEFAULT_INPUTS)
    tasks = read_jsonl(args.tasks)
    development = {row["candidate_id"] for row in tasks if row["experiment_split"] == "development"}
    rows = [row for path in inputs for row in read_jsonl(path)]
    seen = set()
    for row in rows:
        key = (row["method"], row["candidate_id"], row["field"])
        if key in seen:
            raise RuntimeError(f"duplicate prediction: {key}")
        seen.add(key)
        if row["candidate_id"] not in development:
            raise RuntimeError(f"non-development candidate in bundle: {row['candidate_id']}")
        if not isinstance(row.get("prediction"), bool):
            raise RuntimeError(f"non-boolean prediction: {key}")
    rows.sort(key=lambda row: (row["method"], row["field"], row["candidate_id"]))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    grouped = Counter((row["method"], row["field"], row["prediction"]) for row in rows)
    summary = {
        "split": "development",
        "task_candidates": len(development),
        "prediction_rows": len(rows),
        "methods": sorted({row["method"] for row in rows}),
        "counts": {
            f"{method}|{field}|{'positive' if prediction else 'negative'}": count
            for (method, field, prediction), count in sorted(grouped.items())
        },
        "label_inputs_used": False,
        "accuracy_metrics_available": False,
    }
    args.output.with_suffix(".summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
