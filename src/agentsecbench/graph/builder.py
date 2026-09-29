"""Build candidate-centered Security-ADG artifacts from product findings."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

from agentsecbench.models import Finding
from agentsecbench.frameworks import BUILTIN_ADAPTERS, FrameworkAdapter

from .analysis import analyze_source
from .project import PythonProjectIndex, build_python_project_index, expand_interprocedural_sources
from .project_typescript import (
    TypeScriptProjectIndex,
    build_typescript_project_index,
    expand_typescript_sources,
)


SCHEMA_VERSION = "1.0"
GENERATOR = "agentsecbench_security_adg_product_v1"
EFFECTS = {
    "browser_control": "browser_state_or_remote_content",
    "command_execution": "process_or_shell",
    "credential_access": "credential_material",
    "database_access": "persistent_database",
    "dynamic_code_execution": "runtime_interpreter",
    "external_tool_invocation": "external_tool_or_agent",
    "filesystem_delete": "persistent_filesystem",
    "filesystem_read": "filesystem_confidentiality",
    "filesystem_write": "persistent_filesystem",
    "message_or_email_send": "external_recipient",
    "network_access": "remote_network",
    "permission_or_auth_change": "authorization_state",
}


def _node(nodes: list[dict], node_type: str, **attributes: object) -> str:
    identifier = f"n{len(nodes) + 1}"
    nodes.append({"id": identifier, "type": node_type, **attributes})
    return identifier


def _verified(text: str, finding: Finding) -> bool:
    lines = text.splitlines()
    if len(finding.evidence_lines) != len(finding.evidence_line_sha256):
        return False
    for line, expected in zip(finding.evidence_lines, finding.evidence_line_sha256):
        if line < 1 or line > len(lines):
            return False
        actual = hashlib.sha256(lines[line - 1].strip().encode("utf-8", errors="replace")).hexdigest()
        if actual != expected:
            return False
    return True


def build_graph(
    repository: Path,
    finding: Finding,
    adapters: tuple[FrameworkAdapter, ...] = BUILTIN_ADAPTERS,
    project_index: PythonProjectIndex | None = None,
    typescript_index: TypeScriptProjectIndex | None = None,
    source_text: str | None = None,
) -> dict:
    source_path = repository / Path(finding.path)
    text = source_text if source_text is not None else source_path.read_text(encoding="utf-8", errors="replace")
    source_lines = text.splitlines()
    evidence_verified = _verified(text, finding)
    analysis = analyze_source(text, finding.path, finding.evidence_lines, finding.symbol, adapters)
    interprocedural = {"enabled": False, "reason": "project_index_unavailable"}
    if project_index is not None and finding.path.lower().endswith(".py"):
        analysis, interprocedural = expand_interprocedural_sources(
            analysis, finding.path, finding.symbol, project_index,
        )
    elif typescript_index is not None and finding.path.lower().endswith((".js", ".jsx", ".mjs", ".ts", ".tsx")):
        analysis, interprocedural = expand_typescript_sources(
            analysis, finding.path, finding.symbol, typescript_index,
        )
    nodes: list[dict] = []
    edges: list[dict] = []
    symbol = _node(
        nodes, "agent_or_program_symbol", name=finding.symbol,
        agent_relevance="framework_confirmed" if analysis.framework_evidence else "unknown",
        frameworks=sorted({item["framework"] for item in analysis.framework_evidence}),
        framework_evidence=list(analysis.framework_evidence),
    )
    operation = _node(
        nodes, "security_sensitive_operation", name=analysis.operation_name,
        category=finding.category, confidence=finding.confidence,
        detectors=list(finding.detectors), evidence_lines=list(finding.evidence_lines),
        evidence_snippets=[
            {"line": line, "text": source_lines[line - 1][:500]}
            for line in finding.evidence_lines
            if 1 <= line <= len(source_lines)
        ],
    )
    effect = _node(nodes, "external_effect", target_class=EFFECTS.get(finding.category, "external_or_persistent_state"), confirmation="unconfirmed_static_candidate")
    boundary = _node(nodes, "trust_boundary", boundary="less_trusted_input_to_security_sensitive_effect", crossed="unconfirmed_static_candidate")
    edges.extend([
        {"from": symbol, "to": operation, "type": "contains", "status": "structural"},
        {"from": operation, "to": effect, "type": "may_cause", "status": "category_semantics"},
        {"from": boundary, "to": operation, "type": "reaches", "status": "unconfirmed_static_candidate"},
    ])
    source_ids = []
    interprocedural_node_ids: list[str] = []
    for source in analysis.sources:
        source_id = _node(nodes, "input_source", **source)
        source_ids.append(source_id)
        edges.extend([
            {"from": source_id, "to": operation, "type": "may_data_depend_on", "status": "local_static_candidate"},
            {"from": source_id, "to": boundary, "type": "may_cross", "status": "local_static_candidate"},
        ])
        if source.get("interprocedural"):
            chain = [
                part for part in source.get("dependency_path", [])
                if isinstance(part, str)
                and any(f"{suffix}:" in part for suffix in (".py", ".js", ".jsx", ".mjs", ".ts", ".tsx"))
            ]
            previous = source_id
            for qualified in reversed(chain):
                chain_id = _node(
                    nodes,
                    "program_symbol",
                    name=qualified,
                    role="interprocedural_call_chain",
                    evidence="project_call_index_candidate",
                )
                interprocedural_node_ids.append(chain_id)
                edges.append({
                    "from": previous,
                    "to": chain_id,
                    "type": "flows_through",
                    "status": "project_call_candidate",
                })
                previous = chain_id
            edges.append({
                "from": previous,
                "to": operation,
                "type": "flows_through",
                "status": "project_call_candidate",
            })
    guard_ids = []
    for guard in analysis.guards:
        guard_id = _node(nodes, "guard_candidate", **guard, effectiveness="unconfirmed_static_candidate")
        guard_ids.append(guard_id)
        edges.append({"from": guard_id, "to": operation, "type": "may_guard", "status": guard.get("confidence", "candidate")})
    framework_names = sorted({
        *[item["framework"] for item in analysis.framework_evidence],
        *[str(item["framework"]) for item in analysis.sources if item.get("framework")],
    })
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR,
        "graph_id": f"SADG-{finding.finding_id}",
        "candidate_id": finding.finding_id,
        "provenance": {
            "scan_root": str(repository), "file": finding.path,
            "line_start": finding.line_start, "line_end": finding.line_end,
            "finding_fingerprint": finding.fingerprint,
            "evidence_hash_verified": evidence_verified,
            "label_inputs_used": False, "source_execution_used": False,
        },
        "nodes": nodes,
        "edges": edges,
        "analysis": {
            "engine": analysis.engine,
            "operation_line": analysis.operation_line,
            "dependency_paths": [list(item) for item in analysis.dependency_paths],
            "framework_evidence": list(analysis.framework_evidence),
            "interprocedural": interprocedural,
            "limitations": list(analysis.limitations),
        },
        "views": {
            "sink_only": {"nodes": [operation], "edges": []},
            "plain_adg": {"nodes": [symbol, operation, effect], "edges": ["contains", "may_cause"]},
            "security_adg": {
                "nodes": [node["id"] for node in nodes],
                "edges": [edge["type"] for edge in edges],
                "source_candidates": len(source_ids), "guard_candidates": len(guard_ids),
                "dependency_paths": len(analysis.dependency_paths),
                "interprocedural_nodes": len(interprocedural_node_ids),
                "frameworks": framework_names,
            },
        },
        "claim_boundary": "candidate graph; inferred dependencies and guards require review and are not vulnerability claims",
    }


def build_graphs(
    repository: Path,
    findings: tuple[Finding, ...],
    adapters: tuple[FrameworkAdapter, ...] = BUILTIN_ADAPTERS,
    source_texts: dict[str, str] | None = None,
    enable_interprocedural: bool = True,
) -> tuple[tuple[dict, ...], dict]:
    use_index = source_texts is not None and enable_interprocedural
    project_index = build_python_project_index(source_texts or {}, adapters) if use_index else None
    typescript_index = build_typescript_project_index(source_texts or {}, adapters) if use_index else None
    graphs = tuple(
        build_graph(
            repository,
            finding,
            adapters,
            project_index,
            typescript_index,
            source_texts.get(finding.path) if source_texts is not None else None,
        )
        for finding in findings
    )
    frameworks = Counter(
        framework for graph in graphs for framework in graph["views"]["security_adg"]["frameworks"]
    )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "generator": GENERATOR,
        "interprocedural_enabled": enable_interprocedural,
        "graph_count": len(graphs),
        "graphs_with_dependency_path": sum(bool(graph["analysis"]["dependency_paths"]) for graph in graphs),
        "graphs_with_guard_candidate": sum(graph["views"]["security_adg"]["guard_candidates"] > 0 for graph in graphs),
        "graphs_with_framework_evidence": sum(bool(graph["views"]["security_adg"]["frameworks"]) for graph in graphs),
        "graphs_with_interprocedural_source": sum(
            graph["analysis"].get("interprocedural", {}).get("expanded_sources", 0) > 0
            for graph in graphs
        ),
        "project_index": {
            "python_files_indexed": project_index.source_file_count if project_index else 0,
            "functions_indexed": len(project_index.functions) if project_index else 0,
            "callsites_indexed": project_index.callsite_count if project_index else 0,
            "parse_failures": list(project_index.parse_failures) if project_index else [],
            "typescript_files_indexed": typescript_index.source_file_count if typescript_index else 0,
            "typescript_functions_indexed": len(typescript_index.functions) if typescript_index else 0,
            "typescript_callsites_indexed": typescript_index.callsite_count if typescript_index else 0,
        },
        "framework_counts": dict(sorted(frameworks.items())),
    }
    return graphs, summary
