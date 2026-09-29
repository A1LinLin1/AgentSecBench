"""Stable command-line entry point for the AgentSecBench engineering package."""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

from . import __version__
from .scanner import ScanOptions, analyze_repository
from .scanner.engine import AnalysisError
from .config import ConfigError, load_project_config
from .initialization import initialize_project
from .demo import DemoError, run_demo
from .report import build_report
from .schemas import SCHEMA_NAMES, read_schema
from .policy import (
    PolicyError,
    evaluate_policy,
    write_baseline,
    write_policy_markdown,
    write_policy_report,
)


MINIMUM_PYTHON = (3, 11)
OPTIONAL_TOOLS = ("git", "docker", "semgrep", "codeql", "dot")


@dataclass(frozen=True)
class ToolStatus:
    """Availability of one optional external integration."""

    name: str
    available: bool
    path: str | None


@dataclass(frozen=True)
class DoctorReport:
    """Machine-readable environment report returned by ``doctor``."""

    schema_version: str
    agentsecbench_version: str
    status: str
    python_version: str
    python_executable: str
    python_supported: bool
    platform: str
    working_directory: str
    optional_tools: tuple[ToolStatus, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_doctor_report() -> DoctorReport:
    """Inspect the runtime without executing third-party tools or using network."""

    python_supported = sys.version_info >= MINIMUM_PYTHON
    tools = tuple(
        ToolStatus(name=name, available=(path := shutil.which(name)) is not None, path=path)
        for name in OPTIONAL_TOOLS
    )
    return DoctorReport(
        schema_version="1.0",
        agentsecbench_version=__version__,
        status="ready" if python_supported else "unsupported_python",
        python_version=platform.python_version(),
        python_executable=sys.executable,
        python_supported=python_supported,
        platform=platform.platform(),
        working_directory=str(Path.cwd()),
        optional_tools=tools,
    )


def print_human_doctor_report(report: DoctorReport) -> None:
    print(f"AgentSecBench {report.agentsecbench_version}")
    python_mark = "ok" if report.python_supported else "unsupported"
    print(f"Python: {report.python_version} [{python_mark}]")
    print(f"Platform: {report.platform}")
    print(f"Working directory: {report.working_directory}")
    print("Optional integrations:")
    for tool in report.optional_tools:
        detail = tool.path if tool.available else "not found"
        print(f"  {tool.name}: {detail}")
    print(f"Status: {report.status}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentsecbench",
        description="Security-aware static analysis for LLM-agent software.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    doctor = subparsers.add_parser(
        "doctor",
        help="Check the local runtime and optional tool integrations.",
    )
    doctor.add_argument("--json", action="store_true", help="Emit a stable JSON report.")

    demo = subparsers.add_parser(
        "demo",
        help="Run a self-contained authored example and build an offline report.",
    )
    demo.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("agentsecbench-demo"),
        help="New or empty demo directory (default: ./agentsecbench-demo).",
    )
    demo.add_argument("--json", action="store_true", help="Emit a stable JSON result.")

    initialize = subparsers.add_parser(
        "init",
        help="Create a safe default .agentsecbench.toml for a project.",
    )
    initialize.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=Path("."),
        help="Project directory (default: current directory).",
    )
    initialize.add_argument(
        "--force",
        action="store_true",
        help="Replace an existing configuration file.",
    )
    initialize.add_argument("--json", action="store_true", help="Emit a stable JSON result.")

    baseline = subparsers.add_parser(
        "baseline",
        help="Freeze stable fingerprints from a findings.jsonl file.",
    )
    baseline.add_argument(
        "findings",
        type=Path,
        nargs="?",
        default=Path("agentsecbench-results/findings.jsonl"),
        help="Findings JSONL (default: ./agentsecbench-results/findings.jsonl).",
    )
    baseline.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(".agentsecbench-baseline.json"),
        help="Baseline output (default: ./.agentsecbench-baseline.json).",
    )
    baseline.add_argument("--json", action="store_true", help="Emit a stable JSON result.")

    schema = subparsers.add_parser(
        "schema",
        help="List or print bundled machine-readable output schemas.",
    )
    schema.add_argument(
        "name",
        nargs="?",
        choices=SCHEMA_NAMES,
        help="Schema to print; omit to list available schema names.",
    )
    schema.add_argument("--json", action="store_true", help="Emit the schema-name list as JSON.")

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a local repository without executing its code.",
    )
    analyze.add_argument("path", type=Path, help="Local repository or source directory.")
    analyze.add_argument(
        "--config",
        type=Path,
        help="Configuration file (default: PATH/.agentsecbench.toml when present).",
    )
    analyze.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("agentsecbench-results"),
        help="Output directory (default: ./agentsecbench-results).",
    )
    analyze.add_argument(
        "--granularity",
        choices=("line", "symbol"),
        default=None,
        help="Emit one candidate per matched line or aggregate by symbol.",
    )
    analyze.add_argument(
        "--max-file-bytes",
        type=int,
        default=None,
        help="Skip individual source files larger than this limit.",
    )
    analyze.add_argument(
        "--include",
        action="append",
        default=None,
        metavar="GLOB",
        help="Analyze only matching paths; may be repeated.",
    )
    analyze.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="GLOB",
        help="Exclude matching paths; may be repeated.",
    )
    analyze.add_argument("--json", action="store_true", help="Print the summary as JSON.")
    analyze.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Return exit code 3 when one or more review candidates are found.",
    )
    analyze.add_argument(
        "--no-interprocedural",
        action="store_true",
        help="Disable project-level call propagation for ablation or debugging.",
    )
    analyze.add_argument("--baseline", type=Path, help="Override the configured baseline file.")
    analyze.add_argument("--suppressions", type=Path, help="Override the configured suppression file.")
    analyze.add_argument(
        "--block-category",
        action="append",
        default=None,
        metavar="CATEGORY",
        help="Treat only this category as blocking; may be repeated.",
    )
    analyze.add_argument(
        "--minimum-confidence",
        choices=("medium", "high"),
        default=None,
        help="Minimum confidence for a new candidate to block CI.",
    )
    analyze.add_argument(
        "--fail-on-new",
        action="store_true",
        help="Return exit code 4 for new, unsuppressed candidates.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "doctor":
        report = build_doctor_report()
        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        else:
            print_human_doctor_report(report)
        return 0 if report.python_supported else 2
    if args.command == "demo":
        try:
            result = run_demo(args.output)
        except (DemoError, AnalysisError, OSError) as error:
            print(f"agentsecbench: error: {error}", file=sys.stderr)
            return 2
        payload = result.to_dict()
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print("AgentSecBench demo completed.")
            print(f"Authored candidates: {result.candidate_count}")
            print(f"Categories: {', '.join(result.categories)}")
            print(f"Interactive report: {result.report_file}")
            print("No target code was executed. These are demonstration candidates, not vulnerabilities.")
        return 0
    if args.command == "init":
        try:
            result = initialize_project(args.path, force=args.force)
        except (ConfigError, OSError) as error:
            print(f"agentsecbench: error: {error}", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        else:
            print(f"Created configuration: {result.config_file}")
            print(f"Next: {result.next_command}")
        return 0
    if args.command == "baseline":
        try:
            payload = write_baseline(args.findings.expanduser().resolve(), args.output.expanduser().resolve())
        except (PolicyError, OSError) as error:
            print(f"agentsecbench: error: {error}", file=sys.stderr)
            return 2
        result = {
            "status": "created",
            "baseline_file": str(args.output.expanduser().resolve()),
            **payload,
        }
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"Baseline created: {result['baseline_file']}")
            print(f"Stable fingerprints: {payload['unique_fingerprint_count']}")
        return 0
    if args.command == "schema":
        if args.name:
            print(json.dumps(read_schema(args.name), ensure_ascii=False, indent=2))
        elif args.json:
            print(json.dumps({"schema_names": list(SCHEMA_NAMES)}, indent=2))
        else:
            print("Bundled output schemas:")
            for name in SCHEMA_NAMES:
                print(f"- {name}")
        return 0
    if args.command == "analyze":
        try:
            root = args.path.expanduser().resolve()
            project_config = load_project_config(root, args.config)
            result = analyze_repository(
                args.path,
                args.output,
                options=ScanOptions(
                    granularity=args.granularity or project_config.granularity,
                    max_file_bytes=args.max_file_bytes if args.max_file_bytes is not None else project_config.max_file_bytes,
                    include=tuple(args.include) if args.include is not None else project_config.include,
                    exclude=tuple(args.exclude) if args.exclude is not None else project_config.exclude,
                    interprocedural=project_config.interprocedural and not args.no_interprocedural,
                ),
                config=project_config,
            )
        except (AnalysisError, ConfigError, OSError) as error:
            print(f"agentsecbench: error: {error}", file=sys.stderr)
            return 2
        baseline_path = args.baseline.expanduser().resolve() if args.baseline else project_config.baseline_path
        suppressions_path = args.suppressions.expanduser().resolve() if args.suppressions else project_config.suppressions_path
        policy = None
        if baseline_path or suppressions_path or args.fail_on_new:
            try:
                policy = evaluate_policy(
                    result.findings,
                    baseline_path=baseline_path,
                    suppressions_path=suppressions_path,
                    blocking_categories=(
                        tuple(args.block_category)
                        if args.block_category is not None
                        else project_config.blocking_categories
                    ),
                    minimum_confidence=args.minimum_confidence or project_config.minimum_confidence,
                )
                policy_path = Path(args.output).expanduser().resolve() / "policy.json"
                policy_summary_path = Path(args.output).expanduser().resolve() / "policy-summary.md"
                write_policy_report(policy_path, policy)
                write_policy_markdown(policy_summary_path, policy)
                graph_summary = json.loads(
                    (Path(args.output).expanduser().resolve() / "security-adg-summary.json").read_text(encoding="utf-8")
                )
                build_report(
                    result.graphs,
                    graph_summary,
                    result.validation or {},
                    Path(result.summary.report_file).parent,
                    policy=policy,
                )
                policy["policy_file"] = str(policy_path)
                policy["policy_summary_file"] = str(policy_summary_path)
            except (PolicyError, OSError) as error:
                print(f"agentsecbench: error: {error}", file=sys.stderr)
                return 2
        payload = result.summary.to_dict()
        if policy is not None:
            payload["policy"] = {
                key: policy[key]
                for key in (
                    "baseline_configured", "existing_findings", "new_findings",
                    "suppressed_findings", "new_unsuppressed_findings", "blocking_findings",
                    "blocking_category_counts", "policy_filters", "policy_file", "policy_summary_file",
                )
            }
        if args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(f"Files scanned: {result.summary.files_scanned}")
            print(f"Candidate behaviors: {result.summary.candidate_count}")
            print(f"Findings: {result.summary.findings_file}")
            print(f"Security-ADG artifacts: {result.summary.graph_count}")
            print(f"Graphs: {result.summary.security_adg_file}")
            print(f"Validation: {result.summary.validation_file}")
            print(f"Interactive report: {result.summary.report_file}")
            print(f"SARIF: {result.summary.sarif_file}")
            if policy is not None:
                print(
                    "Policy: "
                    f"{policy['new_unsuppressed_findings']} new unsuppressed, "
                    f"{policy['existing_findings']} existing, "
                    f"{policy['suppressed_findings']} suppressed, "
                    f"{policy['blocking_findings']} blocking"
                )
                print(f"Policy report: {policy['policy_file']}")
                print(f"CI summary: {policy['policy_summary_file']}")
            print("Claim boundary: candidates require review and are not vulnerability claims.")
        if args.fail_on_new and policy and policy["blocking_findings"]:
            return 4
        if args.fail_on_findings and result.summary.candidate_count:
            return 3
        return 0
    parser.error(f"unknown command: {args.command}")
    return 2
