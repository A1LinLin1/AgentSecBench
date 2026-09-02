"""Evaluate candidate-level predictions against adjudicated stratified gold labels."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_TASKS = BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl"
DEFAULT_GOLD = BASE_DIR / "annotations" / "adjudicated" / "gold.jsonl"
DEFAULT_PREDICTIONS = BASE_DIR / "analysis" / "method_predictions.jsonl"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "weighted_method_metrics.json"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def safe_divide(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def score(pairs: list[tuple[bool, bool, float]]) -> dict:
    tp = sum(weight for truth, prediction, weight in pairs if truth and prediction)
    fp = sum(weight for truth, prediction, weight in pairs if not truth and prediction)
    fn = sum(weight for truth, prediction, weight in pairs if truth and not prediction)
    tn = sum(weight for truth, prediction, weight in pairs if not truth and not prediction)
    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = (
        safe_divide(2 * precision * recall, precision + recall)
        if precision is not None and recall is not None
        else None
    )
    return {
        "n": len(pairs),
        "weighted_tp": tp,
        "weighted_fp": fp,
        "weighted_fn": fn,
        "weighted_tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tasks", type=Path, default=DEFAULT_TASKS)
    parser.add_argument("--gold", type=Path, default=DEFAULT_GOLD)
    parser.add_argument("--predictions", type=Path, default=DEFAULT_PREDICTIONS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    for path in (args.tasks, args.gold, args.predictions):
        if not path.exists():
            raise SystemExit(f"missing required input: {path}")

    tasks = read_jsonl(args.tasks)
    weights = {row["candidate_id"]: float(row["sample_weight"]) for row in tasks}
    gold_rows = read_jsonl(args.gold)
    gold: dict[tuple[str, str], bool] = {}
    for row in gold_rows:
        candidate = row["candidate_id"]
        labels = row.get("labels", row)
        for field, value in labels.items():
            if isinstance(value, bool):
                gold[(candidate, field)] = value

    grouped: dict[tuple[str, str], list[tuple[bool, bool, float]]] = defaultdict(list)
    seen: set[tuple[str, str, str]] = set()
    ignored = 0
    for row in read_jsonl(args.predictions):
        key = (row["candidate_id"], row["field"])
        prediction_key = (row["method"], *key)
        if prediction_key in seen:
            raise RuntimeError(f"duplicate prediction: {prediction_key}")
        seen.add(prediction_key)
        prediction = row.get("prediction")
        if key not in gold or key[0] not in weights or not isinstance(prediction, bool):
            ignored += 1
            continue
        grouped[(row["method"], row["field"])].append((gold[key], prediction, weights[key[0]]))

    results = {
        "weighting": "inverse inclusion probability (sample_weight)",
        "gold_boolean_cells": len(gold),
        "ignored_predictions": ignored,
        "metrics": {
            f"{method}|{field}": score(pairs)
            for (method, field), pairs in sorted(grouped.items())
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
