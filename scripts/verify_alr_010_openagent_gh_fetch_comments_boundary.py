#!/usr/bin/env python3
"""Boundary/guard verifier for AgentSecBench ALR-010.

ALR-010 confirms that OpenAgent's gh-address-comments helper reaches a
subprocess call. This verifier checks whether that subprocess path is a
vulnerability-level command execution boundary, or a guarded fixed GitHub CLI
helper.

The verifier is source-only. It does not run `gh`, contact GitHub, read
credentials, start OpenAgent, write files, or execute the target helper.
"""

from __future__ import annotations

import argparse
import ast
import json
import time
from pathlib import Path
from typing import Any


REPRODUCTION_ID = "ALR-010"
REPOSITORY = "Haohao-end/openagent"
FROZEN_COMMIT = "4013ab216b543372c214855e6fe1ce4aeb6db5cc"
DEFAULT_REPO = Path("dataset/repos/Haohao-end_openagent")
TARGET_SCRIPT = Path("api/internal/core/skills/catalog/gh-address-comments/scripts/fetch_comments.py")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def line_number(source: str, needle: str) -> int | None:
    for idx, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return idx
    return None


def line_context(source: str, line: int | None, radius: int = 8) -> list[str]:
    if line is None:
        return []
    lines = source.splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return [f"{idx}: {lines[idx - 1]}" for idx in range(start, end + 1)]


def call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        return f"{node.func.value.id}.{node.func.attr}"
    if isinstance(node.func, ast.Name):
        return node.func.id
    return ""


def kw_value(node: ast.Call, key: str) -> Any:
    for kw in node.keywords:
        if kw.arg == key:
            try:
                return ast.literal_eval(kw.value)
            except Exception:
                return type(kw.value).__name__
    return None


def first_arg_shape(node: ast.Call) -> str | None:
    if not node.args:
        return None
    arg = node.args[0]
    if isinstance(arg, ast.List):
        return "List"
    if isinstance(arg, ast.Name):
        return "Name"
    try:
        return repr(ast.literal_eval(arg))
    except Exception:
        return type(arg).__name__


def collect_subprocess_calls(source: str) -> list[dict[str, Any]]:
    tree = ast.parse(source)
    calls: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and call_name(node).startswith("subprocess."):
            calls.append(
                {
                    "line": node.lineno,
                    "name": call_name(node),
                    "first_arg_shape": first_arg_shape(node),
                    "shell": kw_value(node, "shell"),
                    "capture_output": kw_value(node, "capture_output"),
                    "text": kw_value(node, "text"),
                }
            )
    return sorted(calls, key=lambda item: item["line"])


def collect_cli_argument_sources(source: str) -> list[dict[str, Any]]:
    tree = ast.parse(source)
    sources: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = call_name(node)
            if name in {"input", "argparse.ArgumentParser", "parser.add_argument"}:
                sources.append({"line": node.lineno, "name": name})
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if node.value.id == "sys" and node.attr == "argv":
                sources.append({"line": node.lineno, "name": "sys.argv"})
    return sorted(sources, key=lambda item: item["line"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    repo = args.repo.resolve()
    script_path = repo / TARGET_SCRIPT
    evidence: dict[str, Any] = {
        "reproduction_id": REPRODUCTION_ID,
        "validation_id": "ASV-ALR-010-OPENAGENT-GH-HELPER-BOUNDARY",
        "repository": REPOSITORY,
        "frozen_commit": FROZEN_COMMIT,
        "candidate_file": str(TARGET_SCRIPT).replace("\\", "/"),
        "candidate_line": 96,
        "operation": "subprocess.run(cmd, input=stdin, capture_output=True, text=True)",
        "auth_material_supplied": False,
        "payload_safety": "source-only GitHub CLI boundary audit; no gh execution, no network, no credentials, no file write",
        "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "human_labels_used": False,
        "model_labels_used": False,
    }

    try:
        source = read(script_path)
        subprocess_calls = collect_subprocess_calls(source)
        cli_argument_sources = collect_cli_argument_sources(source)
    except Exception as exc:
        evidence.update({"status": "source_or_parse_error", "error": repr(exc)})
        return write_and_print(evidence, args.out, 2)

    candidate_call = next((row for row in subprocess_calls if row["line"] == 96), None)
    source_signals = {
        "candidate_subprocess_call_present": candidate_call is not None,
        "candidate_subprocess_uses_cmd_name": candidate_call is not None
        and candidate_call["first_arg_shape"] == "Name",
        "candidate_does_not_set_shell_true": candidate_call is not None and candidate_call["shell"] is None,
        "candidate_captures_output_as_text": candidate_call is not None
        and candidate_call["capture_output"] is True
        and candidate_call["text"] is True,
        "fixed_gh_auth_status_command": '_run(["gh", "auth", "status"])' in source,
        "fixed_gh_pr_view_command": '["gh", "pr", "view", "--json", fields]' in source,
        "fixed_gh_graphql_command_prefix": '"gh",\n        "api",\n        "graphql",' in source,
        "graphql_query_passed_via_stdin_query_at_dash": '"query=@-"' in source and "stdin=QUERY" in source,
        "github_variables_passed_as_gh_fields": 'f"owner={owner}"' in source
        and 'f"repo={repo}"' in source
        and 'f"number={number}"' in source,
        "script_has_no_cli_user_argument_parser_or_input": cli_argument_sources == [],
        "main_uses_current_pr_ref_then_fetch_all": "owner, repo, number = get_current_pr_ref()" in source
        and "result = fetch_all(owner, repo, number)" in source,
        "read_only_pr_comment_review_fields": "comments(first: 100" in source
        and "reviews(first: 100" in source
        and "reviewThreads(first: 100" in source,
        "requires_existing_gh_authentication": "`gh auth login` already set up" in source
        and "gh auth status failed" in source,
    }
    confirmed = all(source_signals.values())

    evidence.update(
        {
            "source_locations": {
                "candidate_subprocess_line": line_number(source, "p = subprocess.run(cmd"),
                "gh_auth_status_line": line_number(source, '_run(["gh", "auth", "status"])'),
                "gh_pr_view_line": line_number(source, '["gh", "pr", "view", "--json", fields]'),
                "gh_graphql_line": line_number(source, '"graphql",'),
                "main_line": line_number(source, "def main() -> None:"),
            },
            "candidate_context": line_context(source, line_number(source, "p = subprocess.run(cmd")),
            "graphql_context": line_context(source, line_number(source, '"query=@-"'), radius=10),
            "subprocess_calls": subprocess_calls,
            "cli_argument_sources": cli_argument_sources,
            "source_signals": source_signals,
            "real_gh_executed": False,
            "network_used": False,
            "credentials_read_or_supplied": False,
            "shell_executed": False,
            "file_write_performed": False,
            "not_a_vulnerability_claim": confirmed,
            "status": "confirmed_guarded_fixed_gh_cli_readonly_helper_boundary"
            if confirmed
            else "fixed_gh_cli_helper_boundary_not_confirmed",
            "claim_boundary": {
                "classification": (
                    "guarded authenticated GitHub CLI helper for read-only PR comment/review retrieval; "
                    "not a vulnerability-level command execution claim"
                ),
                "why_not_cve_ready": [
                    "The candidate subprocess call receives an argv list object and does not set shell=True.",
                    "The executable and subcommands are fixed GitHub CLI operations: auth status, pr view, and api graphql.",
                    "The GraphQL document is passed through stdin with query=@-, not interpolated into a shell command.",
                    "The script has no argparse/sys.argv/input-based command construction path.",
                    "The operation is a local authenticated helper for reading PR comments/reviews from the current branch context.",
                    "No unauthenticated remote/client boundary, command injection primitive, credential exposure, or write-side effect is established.",
                ],
                "paper_use": (
                    "negative-control / guard-context case showing that Security-ADG should separate "
                    "fixed argv-list tool helpers from vulnerability-level command execution"
                ),
            },
        }
    )
    return write_and_print(evidence, args.out, 0 if confirmed else 1)


def write_and_print(evidence: dict[str, Any], out: Path | None, code: int) -> int:
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(evidence, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2, ensure_ascii=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
