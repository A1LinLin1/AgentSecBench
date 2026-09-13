"""Build a standalone, interactive Security-ADG evidence showcase from JSONL.

The page deliberately presents static-analysis candidates and their local
def-use evidence.  It does not label a candidate as a vulnerability.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
from pathlib import Path

from security_adg_figure import VIEWS, figure_svg


BASE_DIR = Path(__file__).resolve().parent.parent
IMPACT_WEIGHT = {
    "command_execution": 7,
    "dynamic_code_execution": 7,
    "permission_or_auth_change": 7,
    "credential_access": 6,
    "filesystem_delete": 6,
    "external_tool_invocation": 5,
    "network_access": 4,
    "filesystem_write": 4,
    "message_or_email_send": 4,
    "database_access": 4,
    "browser_control": 3,
    "filesystem_read": 3,
}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def operation(graph: dict) -> dict:
    return next(node for node in graph["nodes"] if node["type"] == "security_sensitive_operation")


def select_graphs(graphs: list[dict], candidate_ids: list[str], max_graphs: int) -> list[dict]:
    by_id = {graph["candidate_id"]: graph for graph in graphs}
    if candidate_ids:
        missing = [candidate_id for candidate_id in candidate_ids if candidate_id not in by_id]
        if missing:
            raise ValueError(f"candidate IDs not present in graph file: {', '.join(missing)}")
        return [by_id[candidate_id] for candidate_id in candidate_ids]

    def score(graph: dict) -> tuple[int, str]:
        view = graph.get("views", {}).get("security_adg", {})
        return (
            IMPACT_WEIGHT.get(operation(graph).get("category", ""), 1) * 100
            + view.get("source_candidates", 0) * 20
            + view.get("dependency_paths", 0) * 5
            + view.get("guard_candidates", 0),
            graph["candidate_id"],
        )

    return sorted(graphs, key=lambda graph: (-score(graph)[0], score(graph)[1]))[:max_graphs]


def compact_graph(graph: dict) -> dict:
    op = operation(graph)
    view = graph.get("views", {}).get("security_adg", {})
    nodes = []
    for node in graph["nodes"]:
        detail = node.get("name") or node.get("symbol") or node.get("source_type") or node.get("kind")
        if not detail and node["type"] == "external_effect":
            detail = node.get("target_class")
        if not detail and node["type"] == "trust_boundary":
            detail = node.get("boundary")
        nodes.append({"id": node["id"], "type": node["type"], "label": detail or node["type"]})
    return {
        "candidateId": graph["candidate_id"],
        "repo": graph["provenance"]["repo"],
        "sampleId": graph["provenance"]["sample_id"],
        "commit": graph["provenance"]["commit"],
        "file": graph["provenance"]["file"],
        "category": op.get("category", "unknown"),
        "operation": op.get("name", "security-sensitive operation"),
        "lines": op.get("evidence_lines", []),
        "engine": graph.get("analysis", {}).get("engine", "unknown"),
        "limitations": graph.get("analysis", {}).get("limitations", []),
        "counts": {
            "sources": view.get("source_candidates", 0),
            "guards": view.get("guard_candidates", 0),
            "paths": view.get("dependency_paths", 0),
        },
        "nodes": nodes,
        "edges": graph["edges"],
        "views": graph.get("views", {}),
    }


def page_html(cases: list[dict], source_name: str) -> str:
    encoded = json.dumps(cases, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = Path(__file__).with_name("security_adg_showcase.html").read_text(encoding="utf-8")
    return template.replace("__SOURCE__", html.escape(source_name)).replace("__CASES__", encoded)


def build_showcase(graphs_path: Path, output_dir: Path, candidate_ids: list[str], max_graphs: int) -> dict:
    graphs = read_jsonl(graphs_path)
    selected = select_graphs(graphs, candidate_ids, max_graphs)
    if not selected:
        raise ValueError("no graph records were selected")
    cases = [compact_graph(graph) for graph in selected]
    output_dir.mkdir(parents=True, exist_ok=True)
    figures_dir = output_dir / "figures"
    figures_dir.mkdir(exist_ok=True)
    figure_files = []
    layouts = []
    for index, case in enumerate(cases):
        stem = re.sub(r"[^A-Za-z0-9_.-]", "_", case["candidateId"])
        case["exportStem"] = f"{index+1:02d}-{stem}"
        case["figures"] = {}
        for view in VIEWS:
            svg, plan = figure_svg(case, view)
            name = f"{case['exportStem']}-{view}.svg"
            (figures_dir / name).write_text(svg, encoding="utf-8")
            figure_files.append("figures/" + name)
            case["figures"][view] = svg
            layouts.append({"candidate_id": case["candidateId"], "view": view, **plan})
    (output_dir / "layout.json").write_text(json.dumps(layouts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    page = output_dir / "index.html"
    page.write_text(page_html(cases, graphs_path.name), encoding="utf-8")
    source_digest = hashlib.sha256(graphs_path.read_bytes()).hexdigest()
    manifest = {
        "schema_version": "1.1",
        "renderer": "layered_evidence_svg_v2",
        "purpose": "interactive static-analysis evidence view; not a vulnerability report",
        "source_graphs": str(graphs_path),
        "source_sha256": source_digest,
        "candidate_count": len(cases),
        "candidates": [
            {"candidate_id": case["candidateId"], "repo": case["repo"], "commit": case["commit"], "file": case["file"]}
            for case in cases
        ],
        "files": {"page": "index.html", "figures": figure_files, "layout": "layout.json"},
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--candidate-id", action="append", default=[])
    parser.add_argument("--max-graphs", type=int, default=12)
    args = parser.parse_args()
    if args.max_graphs < 1:
        raise SystemExit("--max-graphs must be at least 1")
    manifest = build_showcase(args.graphs, args.output_dir, args.candidate_id, args.max_graphs)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
