"""Auditable framework-coverage diagnostics for one repository scan."""

from __future__ import annotations

from collections import Counter, defaultdict
import re

from .frameworks import FrameworkAdapter
from .models import Finding


MAX_REPORTED_FILES = 100


def _limited(values: set[str]) -> tuple[list[str], bool]:
    ordered = sorted(values)
    return ordered[:MAX_REPORTED_FILES], len(ordered) > MAX_REPORTED_FILES


def _matches(patterns: tuple[str, ...], text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE | re.MULTILINE) for pattern in patterns)


def build_framework_coverage(
    source_texts: dict[str, str],
    findings: tuple[Finding, ...],
    graphs: tuple[dict, ...],
    adapters: tuple[FrameworkAdapter, ...],
    graph_summary: dict,
) -> dict:
    """Summarize observed signals separately from modeled graph evidence."""

    evidence_by_adapter: dict[str, list[tuple[str, str]]] = defaultdict(list)
    fallback_counts: Counter[str] = Counter()
    candidate_files_with_context: set[str] = set()
    known_adapter_ids = {adapter.adapter_id for adapter in adapters}
    for graph in graphs:
        path = str(graph.get("provenance", {}).get("file") or "")
        candidate_id = str(graph.get("candidate_id") or "")
        evidence = graph.get("analysis", {}).get("framework_evidence", [])
        if evidence and path:
            candidate_files_with_context.add(path)
        for item in evidence:
            adapter_id = str(item.get("adapter_id") or "")
            if item.get("adapter_origin") == "fallback" or adapter_id not in known_adapter_ids:
                fallback_counts[str(item.get("framework") or adapter_id or "unknown")] += 1
                continue
            evidence_by_adapter[adapter_id].append((path, candidate_id))

    adapter_rows = []
    all_signal_files: set[str] = set()
    all_modeled_files: set[str] = set()
    for adapter in adapters:
        signal_files = {
            path
            for path, text in source_texts.items()
            if _matches((*adapter.source_patterns, *adapter.candidate_patterns), text)
        }
        modeled_pairs = evidence_by_adapter.get(adapter.adapter_id, [])
        modeled_files = {path for path, _ in modeled_pairs if path}
        modeled_candidates = {candidate for _, candidate in modeled_pairs if candidate}
        all_signal_files.update(signal_files)
        all_modeled_files.update(modeled_files)
        visible_signals, signals_truncated = _limited(signal_files)
        visible_modeled, modeled_truncated = _limited(modeled_files)
        status = "modeled" if modeled_candidates else "signal_only" if signal_files else "not_observed"
        adapter_rows.append({
            "adapter_id": adapter.adapter_id,
            "name": adapter.name,
            "origin": adapter.origin,
            "languages": list(adapter.languages),
            "status": status,
            "signal_file_count": len(signal_files),
            "signal_files": visible_signals,
            "signal_files_truncated": signals_truncated,
            "modeled_file_count": len(modeled_files),
            "modeled_files": visible_modeled,
            "modeled_files_truncated": modeled_truncated,
            "modeled_candidate_count": len(modeled_candidates),
        })

    candidate_files = {finding.path for finding in findings}
    generic_candidate_files = candidate_files - candidate_files_with_context
    visible_generic, generic_truncated = _limited(generic_candidate_files)
    project_index = graph_summary.get("project_index", {})
    parse_failures = sorted(set(project_index.get("parse_failures", [])))
    statuses = Counter(row["status"] for row in adapter_rows)
    return {
        "schema_version": "1.0",
        "status": "completed",
        "active_adapter_count": len(adapters),
        "adapter_status_counts": dict(sorted(statuses.items())),
        "source_file_count": len(source_texts),
        "framework_signal_file_count": len(all_signal_files),
        "framework_modeled_file_count": len(all_modeled_files),
        "candidate_file_count": len(candidate_files),
        "candidate_files_with_framework_context": len(candidate_files_with_context),
        "generic_candidate_file_count": len(generic_candidate_files),
        "generic_candidate_files": visible_generic,
        "generic_candidate_files_truncated": generic_truncated,
        "fallback_framework_counts": dict(sorted(fallback_counts.items())),
        "parse_failures": parse_failures,
        "adapters": adapter_rows,
        "interpretation": {
            "modeled": "framework evidence is attached to at least one candidate graph",
            "signal_only": "repository text matched a framework signal, but no candidate graph received framework evidence",
            "not_observed": "no source or candidate pattern for this adapter was observed in scanned files",
            "generic_candidate_file": "the file has candidates but no framework context; generic operation analysis still applies",
        },
        "claim_boundary": (
            "Coverage diagnostics describe observed static signals and graph evidence; "
            "they do not establish complete framework support or absence of agent behavior."
        ),
    }
