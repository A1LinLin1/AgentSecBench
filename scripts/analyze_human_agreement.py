"""Compute complete-case Fleiss/Cohen kappa for independent human labels."""

from __future__ import annotations

import argparse
import itertools
import json
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DIR = BASE_DIR / "annotations" / "annotator" / "participants"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "human_agreement.json"
DEFAULT_FIELDS = ("behavior_confirmed", "agent_relevant", "dependency_confirmed", "trust_boundary_crossed")


def read_rows(path: Path) -> dict[str, dict]:
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            rows[row["task_id"]] = row
    return rows


def cohen_kappa(left: list[object], right: list[object]) -> float | None:
    if not left:
        return None
    observed = sum(a == b for a, b in zip(left, right)) / len(left)
    left_counts, right_counts = Counter(left), Counter(right)
    categories = set(left_counts) | set(right_counts)
    expected = sum(left_counts[c] / len(left) * right_counts[c] / len(right) for c in categories)
    return None if expected == 1 else (observed - expected) / (1 - expected)


def fleiss_kappa(ratings: list[list[object]]) -> float | None:
    if not ratings:
        return None
    raters = len(ratings[0])
    if raters < 2 or any(len(row) != raters for row in ratings):
        return None
    categories = sorted({value for row in ratings for value in row}, key=str)
    totals = Counter(value for row in ratings for value in row)
    proportions = {category: totals[category] / (len(ratings) * raters) for category in categories}
    expected = sum(value * value for value in proportions.values())
    observed_items = []
    for row in ratings:
        counts = Counter(row)
        observed_items.append(sum(count * count for count in counts.values()) - raters)
    observed = sum(value / (raters * (raters - 1)) for value in observed_items) / len(ratings)
    return None if expected == 1 else (observed - expected) / (1 - expected)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--field", action="append", dest="fields")
    args = parser.parse_args()
    paths = sorted(args.input_dir.glob("annotator_*.jsonl"))
    if len(paths) < 2:
        raise SystemExit(f"need at least two annotator files in {args.input_dir}")
    annotators = [path.stem.removeprefix("annotator_") for path in paths]
    data = [read_rows(path) for path in paths]
    task_union = sorted(set().union(*(rows.keys() for rows in data)))
    fields = args.fields or list(DEFAULT_FIELDS)
    report = {"annotators": annotators, "task_union": len(task_union), "fields": {}}
    for field in fields:
        complete_tasks = [
            task_id
            for task_id in task_union
            if all(task_id in rows and rows[task_id].get(field) is not None for rows in data)
        ]
        ratings = [[rows[task_id][field] for rows in data] for task_id in complete_tasks]
        pairwise = {}
        for left_index, right_index in itertools.combinations(range(len(data)), 2):
            comparable = [
                task_id
                for task_id in task_union
                if task_id in data[left_index]
                and task_id in data[right_index]
                and data[left_index][task_id].get(field) is not None
                and data[right_index][task_id].get(field) is not None
            ]
            pairwise[f"{annotators[left_index]}__{annotators[right_index]}"] = {
                "n": len(comparable),
                "cohen_kappa": cohen_kappa(
                    [data[left_index][task][field] for task in comparable],
                    [data[right_index][task][field] for task in comparable],
                ),
            }
        report["fields"][field] = {
            "complete_case_n": len(complete_tasks),
            "fleiss_kappa": fleiss_kappa(ratings),
            "pairwise": pairwise,
            "missing_policy": "field-wise complete case",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
