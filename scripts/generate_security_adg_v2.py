"""Generate development-only Security-ADG v2 with local def-use evidence."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from generate_security_adg import BASE_DIR, frozen_files, make_graph, read_jsonl, write_jsonl
from generate_security_adg_showcase import build_showcase
from security_adg_dataflow import analyze


DEFAULT_OUTPUT = BASE_DIR / "graphs" / "security_adg" / "development_v2.jsonl"
DEFAULT_SUMMARY = BASE_DIR / "graphs" / "security_adg" / "development_v2_summary.json"
DEFAULT_GENERATOR = "security_adg_def_use_v2"


def replace_heuristics(graph: dict, analysis, generator: str) -> dict:
    removed = {node["id"] for node in graph["nodes"] if node["type"] in {"input_source", "guard_candidate"}}
    graph["nodes"] = [node for node in graph["nodes"] if node["id"] not in removed]
    graph["edges"] = [edge for edge in graph["edges"] if edge["from"] not in removed and edge["to"] not in removed]
    operation = next(node["id"] for node in graph["nodes"] if node["type"] == "security_sensitive_operation")
    boundary = next(node["id"] for node in graph["nodes"] if node["type"] == "trust_boundary")
    symbol_node = next(node for node in graph["nodes"] if node["type"] == "agent_or_program_symbol")
    if analysis.framework_evidence:
        symbol_node["agent_relevance"] = "framework_confirmed"
        symbol_node["frameworks"] = sorted({item["framework"] for item in analysis.framework_evidence})
        symbol_node["entrypoint_types"] = sorted({item["semantic_role"] for item in analysis.framework_evidence})
        symbol_node["framework_evidence"] = analysis.framework_evidence
    next_id = max(int(node["id"][1:]) for node in graph["nodes"]) + 1
    source_ids = []
    for source in analysis.sources:
        node_id = f"n{next_id}"
        next_id += 1
        graph["nodes"].append({"id": node_id, "type": "input_source", **source})
        source_ids.append(node_id)
        graph["edges"].extend([
            {"from": node_id, "to": operation, "type": "may_data_depend_on", "status": "local_def_use_candidate"},
            {"from": node_id, "to": boundary, "type": "may_cross", "status": "local_def_use_candidate"},
        ])
    guard_ids = []
    for guard in analysis.guards:
        node_id = f"n{next_id}"
        next_id += 1
        graph["nodes"].append({
            "id": node_id,
            "type": "guard_candidate",
            **guard,
            "effectiveness": "unknown_pending_annotation",
        })
        guard_ids.append(node_id)
        graph["edges"].append({"from": node_id, "to": operation, "type": "may_guard", "status": guard["confidence"]})
    graph["schema_version"] = "2.0.0-draft"
    graph["generator"] = generator
    graph["analysis"] = {
        "engine": analysis.engine,
        "operation_line": analysis.operation_line,
        "dependency_paths": analysis.dependency_paths,
        "framework_evidence": analysis.framework_evidence,
        "limitations": analysis.limitations,
    }
    graph["views"]["security_adg"] = {
        "nodes": [node["id"] for node in graph["nodes"]],
        "edges": [edge["type"] for edge in graph["edges"]],
        "source_candidates": len(source_ids),
        "guard_candidates": len(guard_ids),
        "dependency_paths": len(analysis.dependency_paths),
        "frameworks": sorted({item["framework"] for item in analysis.framework_evidence}),
    }
    return graph


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=BASE_DIR / "dataset" / "pilot_manifest.csv")
    parser.add_argument("--findings", type=Path, default=BASE_DIR / "analysis" / "raw_findings.jsonl")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--context-radius", type=int, default=20)
    parser.add_argument("--generator", default=DEFAULT_GENERATOR)
    parser.add_argument("--analysis-mode", choices=("v2_1", "v2_2", "v2_3", "v2_4", "v2_5"), default="v2_1")
    parser.add_argument(
        "--showcase-dir",
        type=Path,
        help="Optional directory for a standalone interactive evidence view generated from this graph output.",
    )
    parser.add_argument("--showcase-max-graphs", type=int, default=12)
    parser.add_argument("--showcase-candidate-id", action="append", default=[])
    parser.add_argument(
        "--split",
        choices=("development", "held_out_evaluation", "mutation_evaluation", "all_corpus"),
        default="development",
        help="all_corpus is an unlabeled descriptive run over every manifest row.",
    )
    args = parser.parse_args()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest = list(csv.DictReader(handle))
    by_repo = {row["repo"]: row for row in manifest}
    findings = [
        row for row in read_jsonl(args.findings)
        if args.split == "all_corpus" or by_repo[row["repo"]].get("experiment_split") == args.split
    ]
    requested_files: dict[str, set[str]] = {}
    for finding in findings:
        requested_files.setdefault(finding["repo"], set()).add(finding["file"])
    cache: dict[tuple[str, str], str] = {}
    repository_cache: dict[str, dict[str, str]] = {}
    graphs = []
    for finding in findings:
        row = by_repo[finding["repo"]]
        key = (finding["repo"], finding["file"])
        if key not in cache:
            if finding["repo"] not in repository_cache:
                repository_cache[finding["repo"]] = frozen_files(
                    (BASE_DIR / row["repository_path"]).resolve(),
                    finding["git_commit"],
                    requested_files[finding["repo"]],
                )
            cache[key] = repository_cache[finding["repo"]][finding["file"]]
        graph = make_graph(finding, row, cache[key], args.context_radius)
        dataflow = analyze(
            cache[key],
            finding["file"],
            finding["evidence_lines"],
            symbol=finding.get("symbol"),
            prefer_parameter_sources=args.analysis_mode in {"v2_2", "v2_3", "v2_4", "v2_5"},
            respect_parameter_overwrites=args.analysis_mode in {"v2_3", "v2_4", "v2_5"},
            include_intrinsic_source_operation=args.analysis_mode not in {"v2_4", "v2_5"},
        )
        if args.analysis_mode == "v2_2":
            dataflow.engine = f"{dataflow.engine}_parameter_precedence_v2_2"
        elif args.analysis_mode == "v2_3":
            dataflow.engine = f"{dataflow.engine}_parameter_precedence_overwrite_v2_3"
        elif args.analysis_mode == "v2_4":
            dataflow.engine = f"{dataflow.engine}_parameter_precedence_overwrite_sink_exclusion_v2_4"
        elif args.analysis_mode == "v2_5":
            dataflow.engine = f"{dataflow.engine}_parameter_precedence_overwrite_sink_exclusion_framework_adaptive_v2_5"
        graphs.append(replace_heuristics(graph, dataflow, args.generator))
    write_jsonl(args.output, graphs)
    engines = Counter(graph["analysis"]["engine"] for graph in graphs)
    engine_stats = {}
    for engine in sorted(engines):
        engine_graphs = [graph for graph in graphs if graph["analysis"]["engine"] == engine]
        engine_stats[engine] = {
            "graphs": len(engine_graphs),
            "with_source": sum(graph["views"]["security_adg"]["source_candidates"] > 0 for graph in engine_graphs),
            "with_guard": sum(graph["views"]["security_adg"]["guard_candidates"] > 0 for graph in engine_graphs),
            "dependency_paths": sum(graph["views"]["security_adg"]["dependency_paths"] for graph in engine_graphs),
        }
    limitation_counts = Counter(
        limitation for graph in graphs for limitation in graph["analysis"]["limitations"]
    )
    source_categories = Counter(
        next(node["category"] for node in graph["nodes"] if node["type"] == "security_sensitive_operation")
        for graph in graphs
        if graph["views"]["security_adg"]["source_candidates"] > 0
    )
    framework_counts = Counter(
        framework
        for graph in graphs
        for framework in graph["views"]["security_adg"].get("frameworks", [])
    )
    summary = {
        "schema_version": "2.0.0-draft",
        "generator": args.generator,
        "analysis_mode": args.analysis_mode,
        "split": args.split,
        "graph_count": len(graphs),
        "repository_count": len({graph["provenance"]["repo"] for graph in graphs}),
        "source_file_count": len(cache),
        "analysis_engines": dict(sorted(engines.items())),
        "engine_stats": engine_stats,
        "limitation_counts": dict(sorted(limitation_counts.items())),
        "source_candidate_categories": dict(sorted(source_categories.items())),
        "framework_counts": dict(sorted(framework_counts.items())),
        "graphs_with_framework_evidence": sum(bool(graph["analysis"].get("framework_evidence")) for graph in graphs),
        "graphs_with_def_use_source": sum(graph["views"]["security_adg"]["source_candidates"] > 0 for graph in graphs),
        "graphs_with_related_guard": sum(graph["views"]["security_adg"]["guard_candidates"] > 0 for graph in graphs),
        "graphs_with_dependency_path": sum(graph["views"]["security_adg"]["dependency_paths"] > 0 for graph in graphs),
        "total_dependency_paths": sum(graph["views"]["security_adg"]["dependency_paths"] for graph in graphs),
        "label_inputs_used": False,
        "held_out_used": args.split == "held_out_evaluation",
        "held_out_labels_used": False,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.showcase_dir:
        if args.showcase_max_graphs < 1:
            raise SystemExit("--showcase-max-graphs must be at least 1")
        showcase = build_showcase(
            args.output,
            args.showcase_dir,
            args.showcase_candidate_id,
            args.showcase_max_graphs,
        )
        summary["showcase"] = showcase
        args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
