"""Safe, deterministic directory scanner for the public product API."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from agentsecbench.models import AnalysisResult, AnalysisSummary, Finding
from agentsecbench.graph import build_graphs, validate_graphs
from agentsecbench.report import build_report
from agentsecbench._version import VERSION
from agentsecbench.config import ProjectConfig, load_project_config
from agentsecbench.frameworks import adapter_registry
from agentsecbench.sarif import write_sarif
from agentsecbench.coverage import build_framework_coverage

from .rules import (
    RULES,
    SOURCE_EXTENSIONS,
    adapter_candidate_rules,
    detector_applies_to_suffix,
    nearest_symbol,
    python_dynamic_operation_lines,
)


DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {
        ".agentsecbench",
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "agentsecbench-results",
        "build",
        "dist",
        "node_modules",
        "target",
        "vendor",
        "venv",
    }
)
DEFAULT_MAX_FILE_BYTES = 2_000_000
MAX_SOURCE_LINE_CHARS = 2_000


class AnalysisError(ValueError):
    """Raised for invalid or unsafe product-level analysis requests."""


@dataclass(frozen=True)
class ScanOptions:
    granularity: str = "line"
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    interprocedural: bool = True

    def validate(self) -> None:
        if self.granularity not in {"line", "symbol"}:
            raise AnalysisError("granularity must be 'line' or 'symbol'")
        if self.max_file_bytes <= 0:
            raise AnalysisError("max_file_bytes must be positive")


@dataclass
class _MatchGroup:
    symbol: str
    lines: set[int] = field(default_factory=set)
    hashes: dict[int, str] = field(default_factory=dict)
    detectors: set[str] = field(default_factory=set)
    evidence: set[str] = field(default_factory=set)
    confidences: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class _CandidateRecord:
    category: str
    confidence: str
    line_start: int
    line_end: int
    evidence_lines: tuple[int, ...]
    evidence_line_sha256: tuple[str, ...]
    match_count: int
    symbol: str
    detectors: tuple[str, ...]
    evidence: tuple[str, ...]


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(Path(path).name, pattern) for pattern in patterns)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _iter_source_files(
    root: Path,
    output_dir: Path,
    options: ScanOptions,
) -> tuple[list[tuple[str, Path]], int, int]:
    files: list[tuple[str, Path]] = []
    skipped_pattern = 0
    directories_pruned = 0
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in sorted(directory_names):
            candidate = current_path / name
            relative = candidate.relative_to(root).as_posix()
            excluded = (
                name in DEFAULT_EXCLUDED_DIRECTORIES
                or candidate.is_symlink()
                or _is_within(candidate.resolve(), output_dir)
                or _matches(relative, options.exclude)
            )
            if excluded:
                directories_pruned += 1
            else:
                kept_directories.append(name)
        directory_names[:] = kept_directories
        for name in sorted(file_names):
            path = current_path / name
            if path.is_symlink() or path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            relative = path.relative_to(root).as_posix()
            if _is_within(path.resolve(), output_dir) or _matches(relative, options.exclude):
                skipped_pattern += 1
                continue
            if options.include and not _matches(relative, options.include):
                skipped_pattern += 1
                continue
            files.append((relative, path))
    return files, skipped_pattern, directories_pruned


def _scan_text(
    relative_path: str,
    text: str,
    granularity: str,
    active_rules: tuple | list = RULES,
) -> list[_CandidateRecord]:
    suffix = Path(relative_path).suffix.lower()
    lines = text.splitlines()
    dynamic_lines = python_dynamic_operation_lines(text) if suffix == ".py" else set()
    grouped: dict[tuple[str, str], _MatchGroup] = {}
    for line_index, source_line in enumerate(lines):
        if len(source_line) > MAX_SOURCE_LINE_CHARS:
            continue
        stripped = source_line.lstrip()
        if stripped.startswith(("#", "//", "/*", "*", '\"\"\"', "'''")):
            continue
        for detector_rule in active_rules:
            if not detector_applies_to_suffix(detector_rule.detector, suffix):
                continue
            if detector_rule.detector == "py_eval_exec" and line_index + 1 not in dynamic_lines:
                continue
            if not detector_rule.pattern.search(source_line):
                continue
            symbol = nearest_symbol(lines, line_index)
            if source_line.lstrip().startswith("@"):
                for following in lines[line_index + 1 : line_index + 9]:
                    candidate = nearest_symbol([following], 0)
                    if candidate != "<module>":
                        symbol = candidate
                        break
            line_number = line_index + 1
            key_symbol = symbol if granularity == "symbol" else f"{symbol}@{line_number}"
            key = (detector_rule.category, key_symbol)
            item = grouped.setdefault(key, _MatchGroup(symbol=symbol))
            item.lines.add(line_number)
            item.hashes[line_number] = hashlib.sha256(
                source_line.strip().encode("utf-8", errors="replace")
            ).hexdigest()
            item.detectors.add(detector_rule.detector)
            item.evidence.add(detector_rule.evidence)
            item.confidences.add(detector_rule.confidence)

    records: list[_CandidateRecord] = []
    for (category, _), item in sorted(grouped.items()):
        evidence_lines = sorted(item.lines)
        persisted_lines = evidence_lines[:50]
        records.append(
            _CandidateRecord(
                category=category,
                confidence="high" if "high" in item.confidences else "medium",
                line_start=evidence_lines[0],
                line_end=evidence_lines[-1],
                evidence_lines=tuple(persisted_lines),
                evidence_line_sha256=tuple(item.hashes[line] for line in persisted_lines),
                match_count=len(evidence_lines),
                symbol=item.symbol,
                detectors=tuple(sorted(item.detectors)),
                evidence=tuple(sorted(item.evidence)),
            )
        )
    return records


def _finding_id(relative_path: str, record: _CandidateRecord) -> str:
    identity = "\0".join(
        (
            relative_path,
            record.category,
            record.symbol,
            str(record.line_start),
            ";".join(record.detectors),
        )
    )
    return "ASB-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16].upper()


def _finding_fingerprint(relative_path: str, record: _CandidateRecord) -> str:
    """Return a line-movement-tolerant identity for baseline comparison."""

    identity = "\0".join(
        (
            relative_path,
            record.category,
            record.symbol,
            ";".join(record.detectors),
            ";".join(sorted(record.evidence_line_sha256)),
        )
    )
    return "ASBFP-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24].upper()


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)


def analyze_repository(
    repository: str | Path,
    output_dir: str | Path,
    *,
    options: ScanOptions | None = None,
    config: ProjectConfig | None = None,
) -> AnalysisResult:
    """Analyze local source without importing, executing, installing, or networking."""

    run_started = time.perf_counter()
    root = Path(repository).expanduser().resolve()
    if not root.exists():
        raise AnalysisError(f"repository path does not exist: {root}")
    if not root.is_dir():
        raise AnalysisError(f"repository path is not a directory: {root}")
    config = config or load_project_config(root)
    options = options or ScanOptions(
        granularity=config.granularity,
        max_file_bytes=config.max_file_bytes,
        include=config.include,
        exclude=config.exclude,
        interprocedural=config.interprocedural,
    )
    options.validate()
    try:
        adapters = adapter_registry(config.framework_adapters)
    except ValueError as error:
        raise AnalysisError(str(error)) from error
    active_rules = [*RULES, *adapter_candidate_rules(config.framework_adapters)]
    destination = Path(output_dir).expanduser().resolve()
    if destination == root:
        raise AnalysisError("output directory must not be the repository root")

    source_files, skipped_pattern, directories_pruned = _iter_source_files(root, destination, options)
    findings: list[Finding] = []
    skipped_size = 0
    skipped_binary = 0
    scanned_files = 0
    source_texts: dict[str, str] = {}
    for relative_path, path in source_files:
        try:
            size = path.stat().st_size
        except OSError:
            skipped_binary += 1
            continue
        if size > options.max_file_bytes:
            skipped_size += 1
            continue
        try:
            content = path.read_bytes()
        except OSError:
            skipped_binary += 1
            continue
        if b"\0" in content[:8192]:
            skipped_binary += 1
            continue
        text = content.decode("utf-8", errors="replace")
        source_texts[relative_path] = text
        scanned_files += 1
        for record in _scan_text(relative_path, text, options.granularity, active_rules):
            findings.append(
                Finding(
                    schema_version="1.0",
                    finding_id=_finding_id(relative_path, record),
                    fingerprint=_finding_fingerprint(relative_path, record),
                    category=record.category,
                    confidence=record.confidence,
                    path=relative_path,
                    line_start=record.line_start,
                    line_end=record.line_end,
                    evidence_lines=record.evidence_lines,
                    evidence_line_sha256=record.evidence_line_sha256,
                    match_count=record.match_count,
                    symbol=record.symbol,
                    detectors=record.detectors,
                    evidence=record.evidence,
                )
            )
    findings.sort(key=lambda item: (item.path, item.line_start, item.category, item.finding_id))
    category_counts = dict(sorted(Counter(item.category for item in findings).items()))
    findings_path = destination / "findings.jsonl"
    graphs_path = destination / "security-adg.jsonl"
    graph_summary_path = destination / "security-adg-summary.json"
    framework_coverage_path = destination / "framework-coverage.json"
    validation_path = destination / "validation.json"
    sarif_path = destination / "results.sarif"
    report_dir = destination / "report"
    summary_path = destination / "summary.json"
    _atomic_write_text(
        findings_path,
        "".join(json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True) + "\n" for item in findings),
    )
    graphs, graph_summary = build_graphs(
        root,
        tuple(findings),
        adapters,
        source_texts,
        enable_interprocedural=options.interprocedural,
    )
    validation = validate_graphs(graphs, expected_candidates=len(findings))
    _atomic_write_text(
        graphs_path,
        "".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in graphs),
    )
    _atomic_write_text(graph_summary_path, json.dumps(graph_summary, ensure_ascii=False, indent=2) + "\n")
    framework_coverage = build_framework_coverage(
        source_texts,
        tuple(findings),
        graphs,
        adapters,
        graph_summary,
    )
    _atomic_write_text(
        framework_coverage_path,
        json.dumps(framework_coverage, ensure_ascii=False, indent=2) + "\n",
    )
    _atomic_write_text(validation_path, json.dumps(validation, ensure_ascii=False, indent=2) + "\n")
    if not validation["valid"]:
        raise AnalysisError(f"generated Security-ADG artifacts failed validation: {validation_path}")
    report_manifest = build_report(
        graphs,
        graph_summary,
        validation,
        report_dir,
        framework_coverage=framework_coverage,
    )
    write_sarif(sarif_path, tuple(findings), VERSION)
    summary = AnalysisSummary(
        schema_version="1.0",
        status="completed",
        scan_root=str(root),
        candidate_granularity=options.granularity,
        files_considered=len(source_files),
        files_scanned=scanned_files,
        files_skipped_size=skipped_size,
        files_skipped_binary=skipped_binary,
        files_skipped_pattern=skipped_pattern,
        directories_pruned=directories_pruned,
        candidate_count=len(findings),
        category_counts=category_counts,
        claim_boundary="static candidates are review targets, not vulnerability claims",
        findings_file=str(findings_path),
        security_adg_file=str(graphs_path),
        validation_file=str(validation_path),
        report_file=str(report_dir / report_manifest["files"]["page"]),
        report_manifest_file=str(report_dir / "manifest.json"),
        sarif_file=str(sarif_path),
        framework_coverage_file=str(framework_coverage_path),
        configuration_file=str(config.path) if config.path else None,
        framework_adapter_count=len(adapters),
        framework_signal_file_count=framework_coverage["framework_signal_file_count"],
        framework_modeled_file_count=framework_coverage["framework_modeled_file_count"],
        generic_candidate_file_count=framework_coverage["generic_candidate_file_count"],
        interprocedural_enabled=options.interprocedural,
        graph_count=graph_summary["graph_count"],
        graphs_with_dependency_path=graph_summary["graphs_with_dependency_path"],
        graphs_with_guard_candidate=graph_summary["graphs_with_guard_candidate"],
        graphs_with_framework_evidence=graph_summary["graphs_with_framework_evidence"],
        graphs_with_interprocedural_source=graph_summary["graphs_with_interprocedural_source"],
        wall_seconds=round(time.perf_counter() - run_started, 6),
    )
    _atomic_write_text(summary_path, json.dumps(summary.to_dict(), ensure_ascii=False, indent=2) + "\n")
    return AnalysisResult(tuple(findings), summary, graphs, validation)
