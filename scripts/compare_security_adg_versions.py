"""Compare label-independent candidate coverage between Security-ADG versions."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def load(path: Path) -> dict[str, dict]:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    return {row["candidate_id"]: row for row in rows}


def present(graph: dict, field: str) -> bool:
    return graph["views"]["security_adg"][field] > 0


def source_signature(graph: dict) -> set[tuple[str, str, str]]:
    return {
        (node.get("source_type", ""), node.get("symbol", ""), node.get("trust", ""))
        for node in graph["nodes"]
        if node["type"] == "input_source"
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v1", type=Path, default=BASE_DIR / "graphs" / "security_adg" / "development.jsonl")
    parser.add_argument("--v2", type=Path, default=BASE_DIR / "graphs" / "security_adg" / "development_v2.jsonl")
    parser.add_argument("--output", type=Path, default=BASE_DIR / "analysis" / "security_adg_v1_v2_comparison.json")
    args = parser.parse_args()
    v1, v2 = load(args.v1), load(args.v2)
    if set(v1) != set(v2):
        raise RuntimeError("candidate sets differ between versions")
    report = {"candidate_count": len(v1), "gold_labels_used": False, "dimensions": {}}
    for dimension in ("source_candidates", "guard_candidates"):
        v1_ids = {item for item, graph in v1.items() if present(graph, dimension)}
        v2_ids = {item for item, graph in v2.items() if present(graph, dimension)}
        report["dimensions"][dimension] = {
            "v1_graphs": len(v1_ids),
            "v2_graphs": len(v2_ids),
            "retained": len(v1_ids & v2_ids),
            "removed": len(v1_ids - v2_ids),
            "added": len(v2_ids - v1_ids),
            "v2_coverage": len(v2_ids) / len(v2),
            "interpretation": "candidate coverage only; not accuracy",
        }
    by_engine = Counter(graph["analysis"]["engine"] for graph in v2.values())
    report["v2_analysis_engines"] = dict(sorted(by_engine.items()))
    report["v2_dependency_paths"] = sum(
        graph["views"]["security_adg"].get("dependency_paths", 0) for graph in v2.values()
    )
    v1_sources = {candidate: source_signature(graph) for candidate, graph in v1.items()}
    v2_sources = {candidate: source_signature(graph) for candidate, graph in v2.items()}
    report["source_node_delta"] = {
        "v1_nodes": sum(len(values) for values in v1_sources.values()),
        "v2_nodes": sum(len(values) for values in v2_sources.values()),
        "graphs_with_changed_sources": sum(v1_sources[key] != v2_sources[key] for key in v1),
        "removed_relations": sum(len(v1_sources[key] - v2_sources[key]) for key in v1),
        "added_relations": sum(len(v2_sources[key] - v1_sources[key]) for key in v1),
        "interpretation": "structural source-node difference only; not an accuracy metric",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
