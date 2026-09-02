"""Materialize reviewer03's model-assisted audit as provisional analysis labels.

This script intentionally does not call the output human ground truth. The
reviewer saw the five-model panel, so the artifact may support development,
case selection, and clearly labelled sensitivity analyses only.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_TASKS = BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl"
DEFAULT_AUDIT = BASE_DIR / "annotations" / "model_audit" / "reviewers" / "reviewer_reviewer03.jsonl"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "provisional" / "reviewer03_model_assisted_labels.jsonl"
DEFAULT_SUMMARY = BASE_DIR / "analysis" / "provisional" / "reviewer03_model_assisted_summary.json"
PRIMARY_FIELDS = (
    "behavior_confirmed",
    "agent_relevant",
    "dependency_confirmed",
    "trust_boundary_crossed",
    "weakness_present",
    "vulnerability_status",
    "effect_type",
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tasks", type=Path, default=DEFAULT_TASKS)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args()

    tasks = {row["task_id"]: row for row in read_jsonl(args.tasks)}
    audit_rows = read_jsonl(args.audit)
    audits = {row["task_id"]: row for row in audit_rows}
    if len(audits) != len(audit_rows):
        raise SystemExit("duplicate task IDs in audit input")
    missing = sorted(set(tasks) - set(audits))
    unexpected = sorted(set(audits) - set(tasks))
    if missing or unexpected:
        raise SystemExit(f"task/audit mismatch: missing={len(missing)}, unexpected={len(unexpected)}")
    if any(row.get("review_type") != "model_assisted_audit" for row in audit_rows):
        raise SystemExit("input is not a model-assisted audit")
    if any(any(row.get(field) is None for field in PRIMARY_FIELDS) for row in audit_rows):
        raise SystemExit("audit has incomplete primary fields")

    labels = []
    for task_id in sorted(tasks):
        task, audit = tasks[task_id], audits[task_id]
        label = {
            **task,
            **{field: audit[field] for field in PRIMARY_FIELDS},
            "rationale": audit.get("rationale", ""),
            "audit_note": audit.get("audit_note", ""),
            "label_provenance": "single_reviewer_model_assisted_audit",
            "ground_truth": False,
            "permitted_use": ["development", "case_selection", "sensitivity_analysis"],
            "prohibited_use": ["human_inter_annotator_agreement", "independent_human_ground_truth"],
            "reviewer": audit.get("reviewer"),
            "model_panel_run_id": audit.get("model_panel_run_id"),
        }
        label["provisional_behavior_positive"] = (
            label["behavior_confirmed"] == "true" and label["agent_relevant"] == "true"
        )
        label["provisional_dependency_positive_strict"] = label["dependency_confirmed"] == "true"
        label["provisional_dependency_positive_inclusive"] = label["dependency_confirmed"] in {"true", "partial"}
        labels.append(label)

    total_weight = sum(float(row["sample_weight"]) for row in labels)
    def weighted_rate(key: str) -> float:
        return sum(float(row["sample_weight"]) for row in labels if row[key]) / total_weight

    summary = {
        "label_set": "reviewer03_model_assisted_audit_provisional_v1",
        "ground_truth": False,
        "interpretation": (
            "Single-reviewer, model-assisted audit labels. They are not independent blind human labels "
            "and must not be used for human agreement, final ground-truth, or held-out method tuning."
        ),
        "records": len(labels),
        "reviewer": labels[0]["reviewer"] if labels else None,
        "model_panel_run_id": labels[0]["model_panel_run_id"] if labels else None,
        "raw_label_counts": {field: dict(Counter(row[field] for row in labels)) for field in PRIMARY_FIELDS},
        "derived_counts": {
            "behavior_positive": sum(row["provisional_behavior_positive"] for row in labels),
            "dependency_positive_strict": sum(row["provisional_dependency_positive_strict"] for row in labels),
            "dependency_positive_inclusive": sum(row["provisional_dependency_positive_inclusive"] for row in labels),
        },
        "weighted_population_estimates": {
            "behavior_positive": weighted_rate("provisional_behavior_positive"),
            "dependency_positive_strict": weighted_rate("provisional_dependency_positive_strict"),
            "dependency_positive_inclusive": weighted_rate("provisional_dependency_positive_inclusive"),
        },
        "by_split": {
            split: sum(1 for row in labels if row["experiment_split"] == split)
            for split in sorted({row["experiment_split"] for row in labels})
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in labels), encoding="utf-8")
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
