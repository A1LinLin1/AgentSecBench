"""Evaluate Security-ADG coverage over reproduction-confirmed GT positives.

This reports recall-style coverage only.  The reproduction GT file contains
positive evidence records, not a sampled negative set, so precision/specificity
are intentionally not computed here.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

try:
    from build_reproduction_gt_findings import finding_id_for_gt
except ModuleNotFoundError:  # pragma: no cover
    from scripts.build_reproduction_gt_findings import finding_id_for_gt


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_GT = BASE_DIR / "analysis" / "ground_truth" / "reproduction_confirmed_gt.jsonl"
DEFAULT_GRAPHS = BASE_DIR / "graphs" / "security_adg" / "reproduction_gt_v2_5.jsonl"
DEFAULT_OUTPUT_DIR = BASE_DIR / "analysis" / "ground_truth" / "coverage"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def graph_summary(graph: dict | None) -> dict:
    if graph is None:
        return {
            "graph_present": False,
            "source_present": False,
            "dependency_path_present": False,
            "guard_present": False,
            "framework_evidence_present": False,
            "source_candidates": 0,
            "dependency_paths": 0,
            "guard_candidates": 0,
        }
    view = graph.get("views", {}).get("security_adg", {})
    analysis = graph.get("analysis", {})
    return {
        "graph_present": True,
        "source_present": int(view.get("source_candidates", 0)) > 0,
        "dependency_path_present": int(view.get("dependency_paths", 0)) > 0,
        "guard_present": int(view.get("guard_candidates", 0)) > 0,
        "framework_evidence_present": bool(analysis.get("framework_evidence")),
        "source_candidates": int(view.get("source_candidates", 0)),
        "dependency_paths": int(view.get("dependency_paths", 0)),
        "guard_candidates": int(view.get("guard_candidates", 0)),
    }


def coverage_stats(rows: list[dict]) -> dict:
    evaluable = [row for row in rows if row["evaluable"]]
    if not evaluable:
        return {
            "evaluable": 0,
            "graph_coverage": None,
            "source_coverage": None,
            "dependency_path_coverage": None,
            "framework_evidence_coverage": None,
        }

    def frac(field: str) -> float:
        return sum(bool(row[field]) for row in evaluable) / len(evaluable)

    return {
        "evaluable": len(evaluable),
        "graph_coverage": frac("graph_present"),
        "source_coverage": frac("source_present"),
        "dependency_path_coverage": frac("dependency_path_present"),
        "framework_evidence_coverage": frac("framework_evidence_present"),
    }


def evaluate(gt_rows: list[dict], graphs: list[dict]) -> tuple[list[dict], dict]:
    graph_by_candidate = {graph.get("candidate_id"): graph for graph in graphs}
    rows: list[dict] = []
    for gt in sorted(gt_rows, key=lambda row: row["gt_id"]):
        candidate_id = finding_id_for_gt(gt["gt_id"])
        has_coordinate = bool(gt.get("candidate_file")) and gt.get("candidate_line") not in (None, "")
        summary = graph_summary(graph_by_candidate.get(candidate_id))
        rows.append(
            {
                "gt_id": gt["gt_id"],
                "candidate_id": candidate_id,
                "repository": gt.get("repository"),
                "behavior_category": gt.get("behavior_category"),
                "behavior_ground_truth": bool(gt.get("behavior_ground_truth")),
                "vulnerability_ground_truth": bool(gt.get("vulnerability_ground_truth")),
                "not_a_vulnerability_claim": bool(gt.get("not_a_vulnerability_claim")),
                "candidate_file": gt.get("candidate_file"),
                "candidate_line": gt.get("candidate_line"),
                "evaluable": has_coordinate,
                "skip_reason": "" if has_coordinate else "missing_candidate_coordinate",
                **summary,
            }
        )

    overall = coverage_stats(rows)
    by_category = {
        category: coverage_stats([row for row in rows if row["behavior_category"] == category])
        for category in sorted({row["behavior_category"] for row in rows})
    }
    by_vulnerability_gt = {
        str(value).lower(): coverage_stats([row for row in rows if row["vulnerability_ground_truth"] is value])
        for value in (False, True)
    }
    summary = {
        "status": "completed",
        "claim_boundary": [
            "Coverage is recall-style over positive reproduction-confirmed GT records.",
            "No precision or specificity is computed because this GT contains no negative sample.",
            "Single-reviewer adjudication and model labels are not used.",
        ],
        "cases": len(rows),
        "evaluable_cases": sum(row["evaluable"] for row in rows),
        "not_evaluable_cases": sum(not row["evaluable"] for row in rows),
        "overall": overall,
        "by_category": by_category,
        "by_vulnerability_ground_truth": by_vulnerability_gt,
        "counts": {
            "graph_present": sum(row["graph_present"] for row in rows),
            "source_present": sum(row["source_present"] for row in rows),
            "dependency_path_present": sum(row["dependency_path_present"] for row in rows),
            "framework_evidence_present": sum(row["framework_evidence_present"] for row in rows),
        },
        "label_inputs_used": False,
        "human_reviewed_sample_used": False,
        "model_labels_used": False,
    }
    return rows, summary


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    parser.add_argument("--graphs", type=Path, default=DEFAULT_GRAPHS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    rows, summary = evaluate(read_jsonl(args.ground_truth), read_jsonl(args.graphs))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows_path = args.output_dir / "reproduction_gt_coverage_records.csv"
    summary_path = args.output_dir / "reproduction_gt_coverage_summary.json"
    write_csv(rows_path, rows)
    summary["records"] = str(rows_path)
    summary["graphs"] = str(args.graphs)
    summary["ground_truth"] = str(args.ground_truth)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
