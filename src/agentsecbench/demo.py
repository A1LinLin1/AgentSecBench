"""Self-contained first-run demonstration for AgentSecBench."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .scanner import analyze_repository


DEMO_SOURCE = '''\
"""Authored static-analysis demo. This file is never executed by AgentSecBench."""

import subprocess
from pathlib import Path


def agent_tool(command: str, workspace: str) -> None:
    """Illustrate agent-facing input reaching two security-sensitive effects."""
    subprocess.run(command, shell=True, check=False)
    Path(workspace, "last-command.txt").write_text(command, encoding="utf-8")
'''


DEMO_README = """# AgentSecBench authored demo

This tiny project exists only to demonstrate static analysis. AgentSecBench
reads `agent.py` as text and does not import or execute it.

The deliberately review-worthy function passes parameters to a shell-capable
process invocation and a filesystem write. These are analysis candidates, not
claims that this authored example is a real vulnerability.
"""


class DemoError(ValueError):
    """Raised when a demo output location cannot be used safely."""


@dataclass(frozen=True)
class DemoResult:
    """Stable summary returned by the first-run demo."""

    schema_version: str
    status: str
    output_directory: str
    sample_directory: str
    report_file: str
    findings_file: str
    security_adg_file: str
    candidate_count: int
    graph_count: int
    categories: tuple[str, ...]
    claim_boundary: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def run_demo(output_directory: Path) -> DemoResult:
    """Create and analyze an authored project without network or code execution."""

    output = output_directory.expanduser().resolve()
    if output.exists():
        if not output.is_dir():
            raise DemoError(f"demo output is not a directory: {output}")
        if any(output.iterdir()):
            raise DemoError(
                f"demo output is not empty: {output}; choose a new directory"
            )

    sample = output / "sample-agent"
    results = output / "results"
    sample.mkdir(parents=True, exist_ok=True)
    (sample / "agent.py").write_text(DEMO_SOURCE, encoding="utf-8")
    (sample / "README.md").write_text(DEMO_README, encoding="utf-8")

    analysis = analyze_repository(sample, results)
    categories = tuple(sorted({finding.category for finding in analysis.findings}))
    return DemoResult(
        schema_version="1.0",
        status="completed",
        output_directory=str(output),
        sample_directory=str(sample),
        report_file=analysis.summary.report_file,
        findings_file=analysis.summary.findings_file,
        security_adg_file=analysis.summary.security_adg_file,
        candidate_count=analysis.summary.candidate_count,
        graph_count=analysis.summary.graph_count,
        categories=categories,
        claim_boundary=(
            "Authored demonstration candidates only; no target code was executed "
            "and no vulnerability claim is made."
        ),
    )
