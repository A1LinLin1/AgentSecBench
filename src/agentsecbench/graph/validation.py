"""Structural validation for generated Security-ADG artifacts."""

from __future__ import annotations

from collections import Counter


REQUIRED_TYPES = {
    "agent_or_program_symbol", "security_sensitive_operation", "external_effect", "trust_boundary",
}


def validate_graphs(graphs: tuple[dict, ...], expected_candidates: int | None = None) -> dict:
    errors: list[dict] = []
    graph_ids: set[str] = set()
    candidate_ids: set[str] = set()
    node_types: Counter[str] = Counter()
    for graph in graphs:
        graph_id = graph.get("graph_id", "<missing>")
        candidate_id = graph.get("candidate_id", "<missing>")
        if graph_id in graph_ids:
            errors.append({"graph_id": graph_id, "code": "duplicate_graph_id"})
        if candidate_id in candidate_ids:
            errors.append({"graph_id": graph_id, "code": "duplicate_candidate_id"})
        graph_ids.add(graph_id)
        candidate_ids.add(candidate_id)
        provenance = graph.get("provenance", {})
        if not provenance.get("evidence_hash_verified"):
            errors.append({"graph_id": graph_id, "code": "evidence_hash_not_verified"})
        if provenance.get("label_inputs_used") or provenance.get("source_execution_used"):
            errors.append({"graph_id": graph_id, "code": "forbidden_input_or_execution"})
        nodes = graph.get("nodes", [])
        node_ids = [node.get("id") for node in nodes]
        if len(node_ids) != len(set(node_ids)):
            errors.append({"graph_id": graph_id, "code": "duplicate_node_id"})
        types = {node.get("type") for node in nodes}
        node_types.update(item for item in types if item)
        missing = sorted(REQUIRED_TYPES - types)
        if missing:
            errors.append({"graph_id": graph_id, "code": "missing_required_node_types", "details": missing})
        known = set(node_ids)
        for edge in graph.get("edges", []):
            if edge.get("from") not in known or edge.get("to") not in known:
                errors.append({"graph_id": graph_id, "code": "dangling_edge", "details": edge})
        view_nodes = set(graph.get("views", {}).get("security_adg", {}).get("nodes", []))
        if view_nodes != known:
            errors.append({"graph_id": graph_id, "code": "incomplete_security_adg_view"})
    if expected_candidates is not None and len(graphs) != expected_candidates:
        errors.append({"graph_id": None, "code": "candidate_graph_count_mismatch", "details": {"expected": expected_candidates, "actual": len(graphs)}})
    return {
        "schema_version": "1.0",
        "valid": not errors,
        "graph_count": len(graphs),
        "unique_candidates": len(candidate_ids),
        "node_type_graph_counts": dict(sorted(node_types.items())),
        "error_count": len(errors),
        "errors": errors,
    }
