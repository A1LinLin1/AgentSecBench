"""Supported Python API for embedding AgentSecBench."""

from __future__ import annotations

from .models import AnalysisResult, AnalysisSummary, Finding
from .graph import build_graphs, validate_graphs
from .report import build_report
from .config import ConfigError, ProjectConfig, load_project_config
from .frameworks import FrameworkAdapter
from .initialization import InitResult, initialize_project
from .sarif import build_sarif
from .policy import PolicyError, evaluate_policy, policy_markdown, write_baseline
from .scanner import ScanOptions, analyze_repository

__all__ = [
    "AnalysisResult",
    "AnalysisSummary",
    "Finding",
    "ScanOptions",
    "analyze_repository",
    "build_graphs",
    "validate_graphs",
    "build_report",
    "build_sarif",
    "ConfigError",
    "FrameworkAdapter",
    "ProjectConfig",
    "load_project_config",
    "InitResult",
    "initialize_project",
    "PolicyError",
    "evaluate_policy",
    "write_baseline",
    "policy_markdown",
]
