"""Stable public data models for local AgentSecBench analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    """One review candidate emitted by the local static scanner."""

    schema_version: str
    finding_id: str
    fingerprint: str
    category: str
    confidence: str
    path: str
    line_start: int
    line_end: int
    evidence_lines: tuple[int, ...]
    evidence_line_sha256: tuple[str, ...]
    match_count: int
    symbol: str
    detectors: tuple[str, ...]
    evidence: tuple[str, ...]
    review_status: str = "candidate"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence_lines"] = list(self.evidence_lines)
        payload["evidence_line_sha256"] = list(self.evidence_line_sha256)
        payload["detectors"] = list(self.detectors)
        payload["evidence"] = list(self.evidence)
        return payload


@dataclass(frozen=True)
class AnalysisSummary:
    """Machine-readable summary of one local repository analysis."""

    schema_version: str
    status: str
    scan_root: str
    candidate_granularity: str
    files_considered: int
    files_scanned: int
    files_skipped_size: int
    files_skipped_binary: int
    files_skipped_pattern: int
    directories_pruned: int
    candidate_count: int
    category_counts: dict[str, int]
    claim_boundary: str
    findings_file: str
    security_adg_file: str
    validation_file: str
    report_file: str
    report_manifest_file: str
    sarif_file: str
    configuration_file: str | None
    framework_adapter_count: int
    interprocedural_enabled: bool
    graph_count: int
    graphs_with_dependency_path: int
    graphs_with_guard_candidate: int
    graphs_with_framework_evidence: int
    graphs_with_interprocedural_source: int
    wall_seconds: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AnalysisResult:
    findings: tuple[Finding, ...]
    summary: AnalysisSummary
    graphs: tuple[dict[str, Any], ...] = ()
    validation: dict[str, Any] | None = None
