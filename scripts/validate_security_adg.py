"""Validate Security-ADG structural and split-isolation invariants."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = BASE_DIR / "graphs" / "security_adg" / "development.jsonl"
REQUIRED_NODE_TYPES = {
    "agent_or_program_symbol",
    "security_sensitive_operation",
    "external_effect",
    "trust_boundary",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--expected-split", default="development")
    args = parser.parse_args()
    graphs = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line]
    if not graphs:
        raise SystemExit("no graphs")
    graph_ids: set[str] = set()
    candidates: set[str] = set()
    types = Counter()
    for graph in graphs:
        graph_id = graph["graph_id"]
        candidate = graph["candidate_id"]
        if graph_id in graph_ids or candidate in candidates:
            raise RuntimeError(f"duplicate graph/candidate: {graph_id}")
        graph_ids.add(graph_id)
        candidates.add(candidate)
        provenance = graph["provenance"]
        if provenance["experiment_split"] != args.expected_split:
            raise RuntimeError(f"split leakage in {graph_id}: {provenance['experiment_split']}")
        if provenance["label_inputs_used"] or provenance["source_execution_used"]:
            raise RuntimeError(f"forbidden input/execution flag in {graph_id}")
        if not provenance["evidence_hash_verified"]:
            raise RuntimeError(f"unverified evidence in {graph_id}")
        node_ids = {node["id"] for node in graph["nodes"]}
        if len(node_ids) != len(graph["nodes"]):
            raise RuntimeError(f"duplicate node id in {graph_id}")
        node_types = {node["type"] for node in graph["nodes"]}
        missing = REQUIRED_NODE_TYPES - node_types
        if missing:
            raise RuntimeError(f"missing node types in {graph_id}: {sorted(missing)}")
        types.update(node_types)
        for edge in graph["edges"]:
            if edge["from"] not in node_ids or edge["to"] not in node_ids:
                raise RuntimeError(f"dangling edge in {graph_id}: {edge}")
        security_nodes = set(graph["views"]["security_adg"]["nodes"])
        if security_nodes != node_ids:
            raise RuntimeError(f"security_adg view incomplete in {graph_id}")
    print(
        json.dumps(
            {"valid": True, "graphs": len(graphs), "unique_candidates": len(candidates), "node_type_graph_counts": types},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
