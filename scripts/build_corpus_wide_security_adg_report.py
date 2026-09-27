"""Build auditable corpus-wide Security-ADG characterization tables.

This is a descriptive static-analysis report.  Counts in this report are
candidate/evidence counts and must not be interpreted as vulnerability counts.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[rank]


def pct(numerator: int, denominator: int) -> float:
    return round(100.0 * numerator / denominator, 2) if denominator else 0.0


def graph_features(graph: dict) -> dict[str, bool]:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    view = graph.get("views", {}).get("security_adg", {})
    framework = bool(graph.get("analysis", {}).get("framework_evidence")) or any(
        node.get("agent_relevance") == "framework_confirmed" for node in nodes
    )
    source = int(view.get("source_candidates", 0)) > 0
    dependency = int(view.get("dependency_paths", 0)) > 0
    guard = int(view.get("guard_candidates", 0)) > 0
    trust_crossing = any(edge.get("type") == "may_cross" for edge in edges)
    effect_model = any(node.get("type") == "external_effect" for node in nodes)
    effect_confirmed = any(
        node.get("type") == "external_effect"
        and node.get("effect_confirmation") not in {None, "unknown_pending_annotation"}
        for node in nodes
    )
    privilege = any(node.get("type") == "privilege_context" for node in nodes)
    return {
        "agent_framework_evidence": framework,
        "source_provenance": source,
        "dependency_path": dependency,
        "trust_crossing_candidate": trust_crossing,
        "privilege_context": privilege,
        "guard_candidate": guard,
        "external_effect_model": effect_model,
        "external_effect_confirmed": effect_confirmed,
    }


def operation_category(graph: dict) -> str:
    return next(
        (node.get("category", "unknown") for node in graph.get("nodes", []) if node.get("type") == "security_sensitive_operation"),
        "unknown",
    )


def summarize_group(graphs: list[dict]) -> dict:
    features = [graph_features(graph) for graph in graphs]
    total = len(graphs)
    result = {"candidates": total}
    for key in graph_features({}).keys():
        count = sum(item[key] for item in features)
        result[key] = count
        result[f"{key}_rate_pct"] = pct(count, total)
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def runtime_summary(scan_run: dict | None, graph_summary: dict | None, graph_count: int) -> dict:
    result = {"available": False}
    stages = []
    combined_by_repo: dict[str, dict] = defaultdict(dict)
    stage_counts = {
        "candidate_extraction": (scan_run or {}).get("candidate_count"),
        "graph_construction": (graph_summary or {}).get("graph_count"),
    }
    for name, source in (("candidate_extraction", scan_run), ("graph_construction", graph_summary)):
        metrics = (source or {}).get("execution_metrics")
        if not metrics:
            continue
        result["available"] = True
        stages.append({
            "stage": name,
            "population_count": stage_counts[name],
            "wall_seconds": metrics.get("wall_seconds"),
            "candidates_per_second": round(
                stage_counts[name] / metrics["wall_seconds"], 3
            ) if stage_counts[name] is not None and metrics.get("wall_seconds") else None,
            "process_peak_rss_bytes": metrics.get("process_peak_rss_bytes"),
            "python_peak_allocated_bytes": metrics.get("python_peak_allocated_bytes"),
        })
        for row in metrics.get("per_repository", []):
            combined_by_repo[row["repo"]][f"{name}_seconds"] = float(row.get("wall_seconds", 0.0))
    observed_counts = [count for count in stage_counts.values() if count is not None]
    population_consistent = bool(observed_counts) and all(count == graph_count for count in observed_counts)
    totals = [sum(row.values()) for row in combined_by_repo.values()] if population_consistent else []
    result.update({
        "stages": stages,
        "report_population_count": graph_count,
        "population_consistent": population_consistent,
        "end_to_end_comparable": population_consistent and len(stages) == 2,
        "population_note": (
            "All supplied runtime stages use the report population."
            if population_consistent
            else "Runtime stages use different candidate populations; do not sum them as an end-to-end measurement."
        ),
        "repositories_profiled": len(totals),
        "median_repository_seconds": round(percentile(totals, 0.50), 6),
        "p90_repository_seconds": round(percentile(totals, 0.90), 6),
        "p95_repository_seconds": round(percentile(totals, 0.95), 6),
        "per_repository": [
            {"repo": repo, **values, "total_seconds": round(sum(values.values()), 6)}
            for repo, values in sorted(combined_by_repo.items())
        ] if population_consistent else [],
    })
    if result["end_to_end_comparable"]:
        total_wall = sum(float(stage.get("wall_seconds") or 0.0) for stage in stages)
        result["end_to_end_wall_seconds"] = round(total_wall, 6)
        result["end_to_end_candidates_per_second"] = round(graph_count / total_wall, 3) if total_wall else None
    else:
        result["end_to_end_wall_seconds"] = None
        result["end_to_end_candidates_per_second"] = None
    return result


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0]) if rows else ["group"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, report: dict) -> None:
    population = report["population"]
    runtime = report["runtime"]
    lines = [
        "# Corpus-wide Security-ADG characterization",
        "",
        "> Candidate/evidence counts only; these values are not vulnerability counts and do not estimate corpus-wide recall.",
        "",
        "## Population",
        "",
        "| Measure | Count | Rate |",
        "|---|---:|---:|",
    ]
    measures = [
        ("Static candidates", "candidates"),
        ("Framework evidence", "agent_framework_evidence"),
        ("Source provenance", "source_provenance"),
        ("Dependency path", "dependency_path"),
        ("Trust-crossing candidate", "trust_crossing_candidate"),
        ("Privilege context", "privilege_context"),
        ("Guard candidate", "guard_candidate"),
        ("External-effect model node", "external_effect_model"),
        ("Confirmed external effect", "external_effect_confirmed"),
    ]
    for label, key in measures:
        rate = "100.00%" if key == "candidates" else f"{population[f'{key}_rate_pct']:.2f}%"
        lines.append(f"| {label} | {population[key]} | {rate} |")
    lines.extend([
        "",
        "## By behavior category",
        "",
        "| Category | Candidates | Dependency | Guard | Trust-crossing |",
        "|---|---:|---:|---:|---:|",
    ])
    for row in report["tables"]["category"]:
        lines.append(
            f"| {row['category']} | {row['candidates']} | "
            f"{row['dependency_path']} ({row['dependency_path_rate_pct']:.2f}%) | "
            f"{row['guard_candidate']} ({row['guard_candidate_rate_pct']:.2f}%) | "
            f"{row['trust_crossing_candidate']} ({row['trust_crossing_candidate_rate_pct']:.2f}%) |"
        )
    lines.extend(["", "## Scalability", ""])
    if not runtime["available"]:
        lines.append("Runtime metrics were not supplied for this report.")
    else:
        lines.extend([
            f"Population consistency: **{runtime['population_consistent']}**.",
            f"End-to-end comparable: **{runtime['end_to_end_comparable']}**.",
            "",
            "| Stage | Population | Wall time (s) | Candidates/s | Peak RSS (MB) | Python peak allocation (MB) |",
            "|---|---:|---:|---:|---:|---:|",
        ])
        for stage in runtime["stages"]:
            peak = stage.get("python_peak_allocated_bytes")
            peak_mb = f"{peak / 1_000_000:.2f}" if peak is not None else "n/a"
            rss = stage.get("process_peak_rss_bytes")
            rss_mb = f"{rss / 1_000_000:.2f}" if rss is not None else "n/a"
            lines.append(
                f"| {stage['stage']} | {stage.get('population_count', 'n/a')} | "
                f"{stage.get('wall_seconds', 0):.3f} | {stage.get('candidates_per_second', 0):.3f} | "
                f"{rss_mb} | {peak_mb} |"
            )
        if runtime["end_to_end_comparable"]:
            lines.extend([
                "",
                f"End-to-end wall time: **{runtime['end_to_end_wall_seconds']:.3f} s**; "
                f"throughput: **{runtime['end_to_end_candidates_per_second']:.3f} candidates/s**.",
                f"Per-repository median/P90/P95: **{runtime['median_repository_seconds']:.3f} / "
                f"{runtime['p90_repository_seconds']:.3f} / {runtime['p95_repository_seconds']:.3f} s**.",
            ])
        profiled = any(stage.get("python_peak_allocated_bytes") is not None for stage in runtime["stages"])
        lines.extend(["", (
            "Memory is Python allocation peak measured by `tracemalloc`, not total process RSS; profiling overhead is included in wall time."
            if profiled
            else "Memory profiling was disabled for this timing run, so wall time excludes `tracemalloc` overhead."
        )])
    lines.extend(["", f"Graph input SHA-256: `{report['provenance']['graphs_sha256']}`", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--graphs", type=Path, required=True)
    parser.add_argument("--graph-summary", type=Path)
    parser.add_argument("--scan-run", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest = list(csv.DictReader(handle))
    metadata = {row["repo"]: row for row in manifest}
    graphs = read_jsonl(args.graphs)

    grouped: dict[str, dict[str, list[dict]]] = {
        "category": defaultdict(list),
        "ecosystem": defaultdict(list),
        "language": defaultdict(list),
    }
    for graph in graphs:
        repo = graph.get("provenance", {}).get("repo", "unknown")
        details = metadata.get(repo, {})
        grouped["category"][operation_category(graph)].append(graph)
        grouped["ecosystem"][details.get("ecosystem", "unknown")].append(graph)
        grouped["language"][details.get("dominant_language", "unknown")].append(graph)

    tables = {}
    for dimension, values in grouped.items():
        rows = [{dimension: name, **summarize_group(items)} for name, items in sorted(values.items())]
        tables[dimension] = rows
        write_csv(args.output_dir / f"by_{dimension}.csv", rows)

    node_counts = [len(graph.get("nodes", [])) for graph in graphs]
    edge_counts = [len(graph.get("edges", [])) for graph in graphs]
    scan_run = json.loads(args.scan_run.read_text(encoding="utf-8")) if args.scan_run and args.scan_run.exists() else None
    graph_summary = json.loads(args.graph_summary.read_text(encoding="utf-8")) if args.graph_summary and args.graph_summary.exists() else None
    overall = summarize_group(graphs)
    report = {
        "schema_version": "1.0",
        "scope": "descriptive static candidate and Security-ADG evidence characterization",
        "claim_boundary": "candidate/evidence counts only; not vulnerability counts and not corpus-wide recall",
        "population": {
            "manifest_repositories": len(manifest),
            "repositories_with_candidates": len({graph.get("provenance", {}).get("repo") for graph in graphs}),
            "source_files_with_candidates": len({(graph.get("provenance", {}).get("repo"), graph.get("provenance", {}).get("file")) for graph in graphs}),
            **overall,
        },
        "provenance": {
            "manifest": str(args.manifest),
            "manifest_sha256": sha256_file(args.manifest),
            "graphs": str(args.graphs),
            "graphs_sha256": sha256_file(args.graphs),
            "graph_summary": str(args.graph_summary) if args.graph_summary else None,
            "scan_run": str(args.scan_run) if args.scan_run else None,
        },
        "graph_size": {
            "median_nodes": percentile(node_counts, 0.50),
            "p95_nodes": percentile(node_counts, 0.95),
            "median_edges": percentile(edge_counts, 0.50),
            "p95_edges": percentile(edge_counts, 0.95),
        },
        "tables": tables,
        "runtime": runtime_summary(scan_run, graph_summary, len(graphs)),
        "labels_used": False,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "corpus_wide_security_adg_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    write_markdown(args.output_dir / "corpus_wide_security_adg_report.md", report)
    print(json.dumps({
        "candidates": overall["candidates"],
        "repositories_with_candidates": report["population"]["repositories_with_candidates"],
        "dependency_path_rate_pct": overall["dependency_path_rate_pct"],
        "guard_candidate_rate_pct": overall["guard_candidate_rate_pct"],
        "runtime_available": report["runtime"]["available"],
        "output": str(args.output_dir),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
