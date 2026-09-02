"""Evaluate one frozen split against explicitly provisional reviewer03 labels.

The output is not a final benchmark result: the labels were produced by a
single reviewer after exposure to model-panel output.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_LABELS = BASE_DIR / "analysis" / "provisional" / "reviewer03_model_assisted_labels.jsonl"
DEFAULT_ADG = BASE_DIR / "graphs" / "security_adg" / "development_v2.jsonl"
DEFAULT_SEMGREP = BASE_DIR / "analysis" / "baselines" / "development" / "semgrep_predictions.jsonl"
DEFAULT_CODEQL = BASE_DIR / "analysis" / "baselines" / "development" / "codeql_predictions.jsonl"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "provisional" / "development_diagnostic_metrics.json"
DEFAULT_ERROR_OUTPUT = BASE_DIR / "analysis" / "provisional" / "security_adg_v2_development_error_queue.jsonl"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def safe_ratio(numerator: float, denominator: float) -> float | None:
    return None if denominator == 0 else numerator / denominator


def binary_diagnostic(rows: list[dict], method: str, field: str, prediction: dict[str, bool], positive: str = "true") -> dict:
    evaluable = [row for row in rows if row[field] in {positive, "false"}]
    counts = Counter()
    weighted = Counter()
    for row in evaluable:
        actual = row[field] == positive
        predicted = bool(prediction.get(row["candidate_id"], False))
        key = "tp" if predicted and actual else "fp" if predicted else "fn" if actual else "tn"
        counts[key] += 1
        weighted[key] += float(row["sample_weight"])
    ppv = safe_ratio(counts["tp"], counts["tp"] + counts["fp"])
    coverage = safe_ratio(counts["tp"], counts["tp"] + counts["fn"])
    weighted_ppv = safe_ratio(weighted["tp"], weighted["tp"] + weighted["fp"])
    return {
        "method": method,
        "field": field,
        "positive_label": positive,
        "excluded_nonbinary_labels": len(rows) - len(evaluable),
        "n": len(evaluable),
        "confusion_matrix": {key: counts[key] for key in ("tp", "fp", "tn", "fn")},
        "sample_ppv": ppv,
        "labeled_candidate_coverage": coverage,
        "sample_weighted_ppv": weighted_ppv,
        "prediction_count": counts["tp"] + counts["fp"],
        "note": "Coverage is restricted to the labeled candidate sample; it is not repository-wide recall.",
    }


def predictions_for_field(rows: list[dict], field: str) -> dict[str, bool]:
    selected = [row for row in rows if row["field"] == field]
    output = {row["candidate_id"]: bool(row["prediction"]) for row in selected}
    if len(output) != len(selected):
        raise SystemExit(f"duplicate prediction rows for field {field}")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--security-adg", type=Path, default=DEFAULT_ADG)
    parser.add_argument("--security-adg-name", default="security_adg_v2")
    parser.add_argument("--semgrep", type=Path, default=DEFAULT_SEMGREP)
    parser.add_argument("--codeql", type=Path, default=DEFAULT_CODEQL)
    parser.add_argument("--codeql-name", default="codeql_security_and_quality_v1")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--error-output", type=Path, default=DEFAULT_ERROR_OUTPUT)
    parser.add_argument("--split", default="development", choices=("development", "held_out_evaluation"))
    args = parser.parse_args()

    all_labels = read_jsonl(args.labels)
    if any(row.get("ground_truth") is not False for row in all_labels):
        raise SystemExit("labels must explicitly state ground_truth=false")
    labels = [row for row in all_labels if row["experiment_split"] == args.split]
    if not labels:
        raise SystemExit(f"no labels for split {args.split}")
    if any(row.get("label_provenance") != "single_reviewer_model_assisted_audit" for row in labels):
        raise SystemExit("unexpected label provenance")

    sample_ids = {row["candidate_id"] for row in labels}
    semgrep = predictions_for_field(read_jsonl(args.semgrep), "behavior_confirmed")
    codeql_rows = read_jsonl(args.codeql)
    codeql_dependency = predictions_for_field(codeql_rows, "dependency_confirmed")
    codeql_weakness = predictions_for_field(codeql_rows, "weakness_present")
    graphs = {row["candidate_id"]: row for row in read_jsonl(args.security_adg)}
    adg_dependency = {
        candidate_id: bool(graphs.get(candidate_id, {}).get("analysis", {}).get("dependency_paths", []))
        for candidate_id in sample_ids
    }
    if any(candidate_id not in semgrep for candidate_id in sample_ids):
        raise SystemExit("missing Semgrep predictions for a sampled task")
    if any(candidate_id not in codeql_dependency for candidate_id in sample_ids):
        raise SystemExit("missing CodeQL dependency predictions for a sampled task")
    if any(candidate_id not in codeql_weakness for candidate_id in sample_ids):
        raise SystemExit("missing CodeQL weakness predictions for a sampled task")
    if any(candidate_id not in graphs for candidate_id in sample_ids):
        raise SystemExit("missing Security-ADG graph for a sampled task")

    static_all_positive = {candidate_id: True for candidate_id in sample_ids}
    results = [
        binary_diagnostic(labels, "static_candidate_extractor_v1", "behavior_confirmed", static_all_positive),
        binary_diagnostic(labels, "semgrep_predefined_sinks_v1", "behavior_confirmed", semgrep),
        binary_diagnostic(labels, args.security_adg_name, "dependency_confirmed", adg_dependency),
        binary_diagnostic(labels, args.codeql_name, "dependency_confirmed", codeql_dependency),
        binary_diagnostic(labels, args.codeql_name, "weakness_present", codeql_weakness),
    ]
    dependency_rows = [row for row in labels if row["dependency_confirmed"] in {"true", "false"}]
    error_queue = []
    for row in dependency_rows:
        observed = row["dependency_confirmed"] == "true"
        predicted = adg_dependency[row["candidate_id"]]
        if observed == predicted:
            continue
        graph = graphs[row["candidate_id"]]
        error_queue.append(
            {
                "candidate_id": row["candidate_id"],
                "task_id": row["task_id"],
                "error_type": "false_positive" if predicted else "false_negative",
                "repo": row["repo"],
                "file": row["file"],
                "evidence_lines": row["evidence_lines"],
                "candidate_behavior": row["candidate_behavior"],
                "reviewer_dependency_confirmed": row["dependency_confirmed"],
                "reviewer_rationale": row["rationale"],
                "reviewer_audit_note": row["audit_note"],
                "adg_dependency_paths": graph["analysis"]["dependency_paths"],
                "adg_limitations": graph["analysis"]["limitations"],
                "label_provenance": "single_reviewer_model_assisted_audit",
                "ground_truth": False,
                "permitted_use": "development_method_tuning_only",
            }
        )
    payload = {
        "evaluation_type": f"provisional_{args.split}_diagnostic",
        "ground_truth": False,
        "interpretation": (
            "Single-reviewer model-assisted labels. Not a final effectiveness evaluation and not evidence "
            "for human inter-annotator agreement or repository-wide recall."
        ),
        "label_set": "reviewer03_model_assisted_audit_provisional_v1",
        "split": args.split,
        "sampled_tasks": len(labels),
        "repositories": sorted({row["repo"] for row in labels}),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.error_output.parent.mkdir(parents=True, exist_ok=True)
    args.error_output.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in error_queue), encoding="utf-8"
    )
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
