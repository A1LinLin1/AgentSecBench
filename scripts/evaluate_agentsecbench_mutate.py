"""Score static scan and Security-ADG against AgentSecBench-Mutate oracles."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
ROOT = BASE_DIR / "benchmarks" / "derived" / "agentsecbench_mutate_v1"
DEFAULT_CATALOG = ROOT / "mutation_catalog.json"
DEFAULT_ALIGNMENT = BASE_DIR / "analysis" / "mutations" / "agentsecbench_mutate_v1_static_alignment.json"
DEFAULT_GRAPHS = BASE_DIR / "graphs" / "security_adg" / "agentsecbench_mutate_v1_v2_3.jsonl"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "mutations" / "agentsecbench_mutate_v1_v2_3_results.json"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def metric(expected: list[bool], predicted: list[bool]) -> dict:
    tp = sum(a and b for a, b in zip(expected, predicted))
    fp = sum(not a and b for a, b in zip(expected, predicted))
    fn = sum(a and not b for a, b in zip(expected, predicted))
    tn = sum(not a and not b for a, b in zip(expected, predicted))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def evaluate(rows: list[dict]) -> dict:
    dependency_expected = [row["oracle"]["dependency"] for row in rows]
    dependency_predicted = [row["observed"]["dependency"] for row in rows]
    source_expected = [row["oracle"]["source_type"] is not None for row in rows]
    source_predicted = [bool(row["observed"]["source_types"]) for row in rows]
    guard_expected = [row["oracle"]["guard_kind"] is not None for row in rows]
    guard_predicted = [bool(row["observed"]["guard_kinds"]) for row in rows]
    expected_types = {
        (row["mutation_id"], row["oracle"]["source_type"])
        for row in rows
        if row["oracle"]["source_type"] is not None
    }
    predicted_types = {
        (row["mutation_id"], source_type)
        for row in rows
        for source_type in row["observed"]["source_types"]
    }
    type_tp = len(expected_types & predicted_types)
    type_fp = len(predicted_types - expected_types)
    type_fn = len(expected_types - predicted_types)
    type_precision = type_tp / (type_tp + type_fp) if type_tp + type_fp else None
    type_recall = type_tp / (type_tp + type_fn) if type_tp + type_fn else None
    type_f1 = 2 * type_precision * type_recall / (type_precision + type_recall) if type_precision is not None and type_recall is not None and type_precision + type_recall else None
    expected_guards = {
        (row["mutation_id"], row["oracle"]["guard_kind"])
        for row in rows
        if row["oracle"]["guard_kind"] is not None
    }
    predicted_guards = {
        (row["mutation_id"], guard_kind)
        for row in rows
        for guard_kind in row["observed"]["guard_kinds"]
    }
    guard_tp = len(expected_guards & predicted_guards)
    guard_fp = len(predicted_guards - expected_guards)
    guard_fn = len(expected_guards - predicted_guards)
    guard_precision = guard_tp / (guard_tp + guard_fp) if guard_tp + guard_fp else None
    guard_recall = guard_tp / (guard_tp + guard_fn) if guard_tp + guard_fn else None
    guard_f1 = 2 * guard_precision * guard_recall / (guard_precision + guard_recall) if guard_precision is not None and guard_recall is not None and guard_precision + guard_recall else None
    return {
        "static_detection_rate": sum(row["static_detected"] for row in rows) / len(rows) if rows else None,
        "candidate_only_dependency": metric(
            dependency_expected,
            [row["static_detected"] for row in rows],
        ),
        "dependency": metric(dependency_expected, dependency_predicted),
        "source_presence": metric(source_expected, source_predicted),
        "guard_presence": metric(guard_expected, guard_predicted),
        "guard_kind_relation": {"tp": guard_tp, "fp": guard_fp, "fn": guard_fn, "precision": guard_precision, "recall": guard_recall, "f1": guard_f1},
        "source_type_relation": {"tp": type_tp, "fp": type_fp, "fn": type_fn, "precision": type_precision, "recall": type_recall, "f1": type_f1},
        "exact_oracle_matches": sum(
            row["oracle"]["dependency"] == row["observed"]["dependency"]
            and set(row["observed"]["source_types"])
            == ({row["oracle"]["source_type"]} if row["oracle"]["source_type"] is not None else set())
            and set(row["observed"]["guard_kinds"])
            == ({row["oracle"]["guard_kind"]} if row["oracle"]["guard_kind"] is not None else set())
            for row in rows
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--alignment", type=Path, default=DEFAULT_ALIGNMENT)
    parser.add_argument("--graphs", type=Path, default=DEFAULT_GRAPHS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    alignment = json.loads(args.alignment.read_text(encoding="utf-8"))["rows"]
    by_mutation = {row["mutation_id"]: row for row in alignment}
    graphs = {graph["candidate_id"]: graph for graph in read_jsonl(args.graphs)}
    rows = []
    for mutation in catalog["mutations"]:
        aligned = by_mutation[mutation["mutation_id"]]
        candidate_ids = aligned["candidate_ids"]
        graph = graphs.get(candidate_ids[0]) if candidate_ids else None
        source_nodes = [node for node in graph["nodes"] if node["type"] == "input_source"] if graph else []
        guard_nodes = [node for node in graph["nodes"] if node["type"] == "guard_candidate"] if graph else []
        rows.append({
            "mutation_id": mutation["mutation_id"],
            "source_sample_id": mutation.get("source_sample_id"),
            "source_repo": mutation.get("source_repo"),
            "language": mutation["language"],
            "category": mutation["category"],
            "oracle": mutation["oracle"],
            "static_detected": aligned["static_detected"],
            "candidate_id": candidate_ids[0] if candidate_ids else None,
            "observed": {
                "graph_present": graph is not None,
                "dependency": bool(graph and graph["views"]["security_adg"]["dependency_paths"]),
                "source_types": sorted({node["source_type"] for node in source_nodes}),
                "guard_kinds": sorted({node["kind"] for node in guard_nodes}),
                "dependency_paths": graph["analysis"]["dependency_paths"] if graph else [],
            },
        })
    grouped: dict[str, list[dict]] = defaultdict(list)
    by_source_repository: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        grouped[row["language"]].append(row)
        by_source_repository[f"{row.get('source_sample_id') or 'unknown'}:{row.get('source_repo') or 'unknown'}"].append(row)
    report = {
        "suite": catalog["metadata"]["suite"],
        "ground_truth": "controlled source-level mutation oracle",
        "mutation_count": len(rows),
        "overall": evaluate(rows),
        "by_language": {language: evaluate(items) for language, items in sorted(grouped.items())},
        "by_source_repository": {
            source: evaluate(items) for source, items in sorted(by_source_repository.items())
        },
        "mismatches": [
            row for row in rows
            if row["oracle"]["dependency"] != row["observed"]["dependency"]
            or set(row["observed"]["source_types"])
            != ({row["oracle"]["source_type"]} if row["oracle"]["source_type"] is not None else set())
            or set(row["observed"]["guard_kinds"])
            != ({row["oracle"]["guard_kind"]} if row["oracle"]["guard_kind"] is not None else set())
        ],
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"suite": report["suite"], "mutation_count": report["mutation_count"], "overall": report["overall"], "mismatch_count": len(report["mismatches"])}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
