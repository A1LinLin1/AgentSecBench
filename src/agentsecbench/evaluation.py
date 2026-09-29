"""Paired evaluation utilities for intraprocedural/interprocedural ablation."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


class EvaluationError(ValueError):
    """Raised when two graph populations are not safely comparable."""


def read_jsonl(path: Path) -> tuple[dict, ...]:
    return tuple(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())


def _operation(graph: dict) -> dict:
    return next(node for node in graph.get("nodes", []) if node.get("type") == "security_sensitive_operation")


def _identity(graph: dict) -> tuple:
    operation = _operation(graph)
    provenance = graph.get("provenance", {})
    return (
        provenance.get("file"),
        provenance.get("line_start"),
        provenance.get("line_end"),
        operation.get("category"),
        tuple(operation.get("evidence_lines", [])),
    )


def _path_set(graph: dict) -> set[tuple[str, ...]]:
    return {tuple(str(part) for part in path) for path in graph.get("analysis", {}).get("dependency_paths", [])}


def compare_interprocedural_graphs(
    baseline_graphs: tuple[dict, ...],
    enhanced_graphs: tuple[dict, ...],
    baseline_summary: dict | None = None,
    enhanced_summary: dict | None = None,
) -> dict:
    baseline = {graph["candidate_id"]: graph for graph in baseline_graphs}
    enhanced = {graph["candidate_id"]: graph for graph in enhanced_graphs}
    if len(baseline) != len(baseline_graphs) or len(enhanced) != len(enhanced_graphs):
        raise EvaluationError("graph inputs contain duplicate candidate ids")
    if baseline.keys() != enhanced.keys():
        raise EvaluationError(
            f"candidate populations differ: baseline_only={len(baseline.keys() - enhanced.keys())}, "
            f"enhanced_only={len(enhanced.keys() - baseline.keys())}"
        )
    mismatched = [candidate for candidate in baseline if _identity(baseline[candidate]) != _identity(enhanced[candidate])]
    if mismatched:
        raise EvaluationError(f"candidate coordinates/categories differ for {len(mismatched)} records")

    deltas = []
    languages = Counter()
    depths = Counter()
    for candidate_id in sorted(baseline):
        before, after = baseline[candidate_id], enhanced[candidate_id]
        before_view = before.get("views", {}).get("security_adg", {})
        after_view = after.get("views", {}).get("security_adg", {})
        before_paths, after_paths = _path_set(before), _path_set(after)
        added_paths = sorted(after_paths - before_paths)
        removed_paths = sorted(before_paths - after_paths)
        inter = after.get("analysis", {}).get("interprocedural", {})
        sources = [node for node in after.get("nodes", []) if node.get("type") == "input_source" and node.get("interprocedural")]
        for source in sources:
            languages[inter.get("language", "unknown")] += 1
            depths[str(source.get("call_depth", "unknown"))] += 1
        added_program_nodes = [
            node for node in after.get("nodes", [])
            if node.get("type") == "program_symbol" and node.get("role") == "interprocedural_call_chain"
        ]
        changed = bool(added_paths or sources or added_program_nodes)
        if changed:
            operation = _operation(after)
            deltas.append({
                "candidate_id": candidate_id,
                "file": after["provenance"].get("file"),
                "line": after["provenance"].get("line_start"),
                "category": operation.get("category"),
                "language": inter.get("language", "unknown"),
                "added_dependency_paths": [list(path) for path in added_paths],
                "replaced_intraprocedural_paths": [list(path) for path in removed_paths],
                "added_source_count": len(sources),
                "added_call_chain_nodes": [node.get("name") for node in added_program_nodes],
                "max_call_depth": max((int(source.get("call_depth", 0)) for source in sources), default=0),
                "frameworks_before": before_view.get("frameworks", []),
                "frameworks_after": after_view.get("frameworks", []),
            })

    def aggregate(graphs: tuple[dict, ...]) -> dict:
        return {
            "graphs": len(graphs),
            "graphs_with_dependency_path": sum(bool(_path_set(graph)) for graph in graphs),
            "total_dependency_paths": sum(len(_path_set(graph)) for graph in graphs),
            "graphs_with_source_candidate": sum(graph.get("views", {}).get("security_adg", {}).get("source_candidates", 0) > 0 for graph in graphs),
            "graphs_with_framework_evidence": sum(bool(graph.get("views", {}).get("security_adg", {}).get("frameworks")) for graph in graphs),
            "interprocedural_source_nodes": sum(
                node.get("type") == "input_source" and bool(node.get("interprocedural"))
                for graph in graphs for node in graph.get("nodes", [])
            ),
            "call_chain_nodes": sum(
                node.get("type") == "program_symbol" and node.get("role") == "interprocedural_call_chain"
                for graph in graphs for node in graph.get("nodes", [])
            ),
        }

    base_metrics, enhanced_metrics = aggregate(baseline_graphs), aggregate(enhanced_graphs)
    numeric_delta = {
        key: enhanced_metrics[key] - base_metrics[key]
        for key in base_metrics
        if isinstance(base_metrics[key], int)
    }
    baseline_seconds = (baseline_summary or {}).get("wall_seconds")
    enhanced_seconds = (enhanced_summary or {}).get("wall_seconds")
    runtime = {
        "baseline_seconds": baseline_seconds,
        "enhanced_seconds": enhanced_seconds,
        "measurement_note": "one observed run per mode; report descriptively, not as a stable performance estimate",
    }
    if isinstance(baseline_seconds, (int, float)) and isinstance(enhanced_seconds, (int, float)):
        runtime["absolute_overhead_seconds"] = round(enhanced_seconds - baseline_seconds, 6)
        runtime["relative_overhead_percent"] = round(
            ((enhanced_seconds / baseline_seconds) - 1) * 100, 3,
        ) if baseline_seconds else None
    return {
        "schema_version": "1.0",
        "evaluation": "paired_intraprocedural_vs_interprocedural_security_adg",
        "claim_boundary": "static-analysis representation delta; not precision, recall, or vulnerability ground truth",
        "population_alignment": {
            "candidate_ids_equal": True,
            "candidate_coordinates_equal": True,
            "candidate_count": len(baseline),
        },
        "baseline": base_metrics,
        "interprocedural": enhanced_metrics,
        "delta": numeric_delta,
        "path_refinement": {
            "added_interprocedural_paths": sum(
                len(item["added_dependency_paths"]) for item in deltas
            ),
            "replaced_intraprocedural_paths": sum(
                len(item["replaced_intraprocedural_paths"]) for item in deltas
            ),
        },
        "language_source_contributions": dict(sorted(languages.items())),
        "call_depth_distribution": dict(sorted(depths.items(), key=lambda item: str(item[0]))),
        "runtime": runtime,
        "changed_candidate_count": len(deltas),
        "candidate_deltas": deltas,
    }


def markdown_report(report: dict) -> str:
    rows = []
    labels = {
        "graphs": "Candidate graphs",
        "graphs_with_dependency_path": "Graphs with dependency path",
        "total_dependency_paths": "Dependency paths",
        "graphs_with_source_candidate": "Graphs with source candidate",
        "graphs_with_framework_evidence": "Graphs with framework evidence",
        "interprocedural_source_nodes": "Interprocedural source nodes",
        "call_chain_nodes": "Call-chain nodes",
    }
    for key, label in labels.items():
        rows.append(f"| {label} | {report['baseline'][key]} | {report['interprocedural'][key]} | {report['delta'][key]:+d} |")
    candidate_rows = [
        f"| `{item['candidate_id']}` | `{item['file']}:{item['line']}` | {item['language']} | {item['added_source_count']} | {len(item['added_dependency_paths'])} | {item['max_call_depth']} |"
        for item in report["candidate_deltas"]
    ] or ["| — | — | — | 0 | 0 | 0 |"]
    return "\n".join([
        "# Interprocedural Security-ADG Delta",
        "",
        "> Static-analysis representation delta; not precision, recall, or vulnerability ground truth.",
        "",
        "| Metric | Intraprocedural | Interprocedural | Delta |",
        "|---|---:|---:|---:|",
        *rows,
        "",
        "## Changed candidates",
        "",
        "| Candidate | Location | Language | Added sources | Added paths | Max depth |",
        "|---|---|---|---:|---:|---:|",
        *candidate_rows,
        "",
        f"Language contributions: `{json.dumps(report['language_source_contributions'], sort_keys=True)}`",
        "",
        f"Call-depth distribution: `{json.dumps(report['call_depth_distribution'], sort_keys=True)}`",
        "",
        f"Path refinement: `{json.dumps(report['path_refinement'], sort_keys=True)}`",
        "",
        f"Runtime note: {report['runtime']['measurement_note']}",
        "",
    ])
