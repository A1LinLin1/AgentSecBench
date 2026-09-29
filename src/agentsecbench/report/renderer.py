"""Render a deterministic, dependency-free interactive analysis report."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from pathlib import Path


REPORT_SCHEMA = "1.1"
RENDERER = "agentsecbench_offline_report_v2"


def _safe_json(value: object) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _compact_graph(graph: dict) -> dict:
    operation = next(
        (node for node in graph.get("nodes", []) if node.get("type") == "security_sensitive_operation"),
        {},
    )
    provenance = graph.get("provenance", {})
    view = graph.get("views", {}).get("security_adg", {})
    return {
        "candidateId": graph.get("candidate_id"),
        "graphId": graph.get("graph_id"),
        "fingerprint": provenance.get("finding_fingerprint"),
        "file": provenance.get("file", ""),
        "lineStart": provenance.get("line_start"),
        "lineEnd": provenance.get("line_end"),
        "evidenceVerified": bool(provenance.get("evidence_hash_verified")),
        "category": operation.get("category", "unknown"),
        "confidence": operation.get("confidence", "unknown"),
        "operation": operation.get("name", "security-sensitive operation"),
        "evidenceLines": operation.get("evidence_lines", []),
        "evidenceSnippets": operation.get("evidence_snippets", []),
        "detectors": operation.get("detectors", []),
        "engine": graph.get("analysis", {}).get("engine", "unknown"),
        "dependencyPaths": graph.get("analysis", {}).get("dependency_paths", []),
        "frameworkEvidence": graph.get("analysis", {}).get("framework_evidence", []),
        "frameworks": view.get("frameworks", []),
        "interprocedural": graph.get("analysis", {}).get("interprocedural", {}),
        "limitations": graph.get("analysis", {}).get("limitations", []),
        "counts": {
            "sources": view.get("source_candidates", 0),
            "guards": view.get("guard_candidates", 0),
            "paths": view.get("dependency_paths", 0),
        },
        "nodes": graph.get("nodes", []),
        "edges": graph.get("edges", []),
        "views": graph.get("views", {}),
        "claimBoundary": graph.get("claim_boundary", "static candidate; not a vulnerability claim"),
    }


def build_report(
    graphs: tuple[dict, ...],
    graph_summary: dict,
    validation: dict,
    output_dir: Path,
    policy: dict | None = None,
) -> dict:
    """Write a self-contained HTML report and a machine-readable manifest."""

    output_dir.mkdir(parents=True, exist_ok=True)
    cases = [_compact_graph(graph) for graph in graphs]
    policy_by_candidate = {
        item.get("finding_id"): item
        for item in (policy or {}).get("findings", [])
        if item.get("finding_id")
    }
    for case in cases:
        record = policy_by_candidate.get(case["candidateId"])
        case["policy"] = ({
            "baselineStatus": record.get("baseline_status"),
            "suppressed": bool(record.get("suppressed")),
            "suppressionId": record.get("suppression_id"),
            "policyMatch": bool(record.get("policy_match")),
            "blocking": bool(record.get("blocking")),
        } if record else None)
    policy_summary = None
    if policy is not None:
        policy_summary = {
            key: policy.get(key)
            for key in (
                "baseline_configured", "existing_findings", "new_findings",
                "suppressed_findings", "new_unsuppressed_findings", "blocking_findings",
                "blocking_category_counts", "policy_filters", "expired_suppressions",
            )
        }
    payload = {
        "schemaVersion": REPORT_SCHEMA,
        "purpose": "interactive static-analysis evidence view; not a vulnerability report",
        "reviewStorageKey": "agentsecbench-review-v1-" + hashlib.sha256(
            "\0".join(str(case.get("candidateId") or "") for case in cases).encode("utf-8")
        ).hexdigest()[:16],
        "summary": graph_summary,
        "validation": validation,
        "policy": policy_summary,
        "cases": cases,
    }
    template = files("agentsecbench.report").joinpath("template.html").read_text(encoding="utf-8")
    page_text = template.replace("__AGENTSECBENCH_REPORT_DATA__", _safe_json(payload))
    page = output_dir / "index.html"
    page.write_text(page_text, encoding="utf-8", newline="\n")
    page_sha256 = hashlib.sha256(page.read_bytes()).hexdigest()
    manifest = {
        "schema_version": REPORT_SCHEMA,
        "renderer": RENDERER,
        "purpose": payload["purpose"],
        "candidate_count": len(cases),
        "validation_passed": bool(validation.get("valid")),
        "policy_embedded": policy is not None,
        "category_counts": dict(sorted(
            {category: sum(case["category"] == category for case in cases) for category in {case["category"] for case in cases}}.items()
        )),
        "files": {"page": "index.html"},
        "page_sha256": page_sha256,
    }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest
