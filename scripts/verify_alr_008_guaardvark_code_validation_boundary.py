#!/usr/bin/env python3
"""Boundary/guard verifier for AgentSecBench ALR-008.

ALR-008 confirms that guaardvark's code validation handler reaches
`compile(code_content, "<string>", "exec")`. This verifier checks whether that
path is vulnerability-level local code execution, or compile-only syntax
validation with optional LLM-based code review.

The verifier is source-only. It does not import or run guaardvark, contact an
LLM service, execute user code, write files, or use the network.
"""

from __future__ import annotations

import argparse
import ast
import json
import textwrap
import time
from pathlib import Path
from typing import Any


REPRODUCTION_ID = "ALR-008"
REPOSITORY = "guaardvark/guaardvark"
FROZEN_COMMIT = "1742fd5d70455fb5775c69d12a06b170e6c8f311"
DEFAULT_REPO = Path("dataset/repos/guaardvark_guaardvark")
TARGET_SCRIPT = Path("backend/services/task_handlers/code_operations_handler.py")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def line_number(source: str, needle: str) -> int | None:
    for idx, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return idx
    return None


def line_number_after(source: str, needle: str, after: int | None) -> int | None:
    for idx, line in enumerate(source.splitlines(), start=1):
        if after is not None and idx <= after:
            continue
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


def arg_literal(node: ast.Call, index: int) -> Any:
    if len(node.args) <= index:
        return None
    try:
        return ast.literal_eval(node.args[index])
    except Exception:
        return type(node.args[index]).__name__


def collect_exec_family_calls(source: str) -> list[dict[str, Any]]:
    tree = ast.parse(source)
    calls: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and call_name(node) in {"compile", "exec", "eval"}:
            calls.append(
                {
                    "line": node.lineno,
                    "name": call_name(node),
                    "arg0_shape": arg_literal(node, 0),
                    "mode": arg_literal(node, 2) if call_name(node) == "compile" else None,
                }
            )
    return sorted(calls, key=lambda item: item["line"])


def function_source(source: str, function_name: str) -> str:
    tree = ast.parse(source)
    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            end = getattr(node, "end_lineno", node.lineno)
            snippet = textwrap.dedent("\n".join(lines[node.lineno - 1 : end]))
            if snippet.startswith(" "):
                first = next((line for line in snippet.splitlines() if line.strip()), "")
                prefix_len = len(first) - len(first.lstrip(" "))
                if prefix_len:
                    snippet = "\n".join(
                        line[prefix_len:] if line.startswith(" " * prefix_len) else line
                        for line in snippet.splitlines()
                    )
            return snippet
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    repo = args.repo.resolve()
    script_path = repo / TARGET_SCRIPT
    evidence: dict[str, Any] = {
        "reproduction_id": REPRODUCTION_ID,
        "validation_id": "ASV-ALR-008-GUAARDVARK-COMPILE-ONLY-BOUNDARY",
        "repository": REPOSITORY,
        "frozen_commit": FROZEN_COMMIT,
        "candidate_file": str(TARGET_SCRIPT).replace("\\", "/"),
        "candidate_line": 886,
        "operation": "compile(code_content, '<string>', 'exec')",
        "auth_material_supplied": False,
        "payload_safety": "source-only compile boundary audit; no code execution, no LLM call, no network, no file write",
        "started_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "human_labels_used": False,
        "model_labels_used": False,
    }

    try:
        source = read(script_path)
        exec_family_calls = collect_exec_family_calls(source)
        validate_source = function_source(source, "_execute_validate")
    except Exception as exc:
        evidence.update({"status": "source_or_parse_error", "error": repr(exc)})
        return write_and_print(evidence, args.out, 2)

    validate_exec_calls = collect_exec_family_calls(validate_source)
    compile_call = next((row for row in validate_exec_calls if row["name"] == "compile"), None)
    source_signals = {
        "validate_handler_present": bool(validate_source),
        "candidate_compile_exec_mode_present": compile_call is not None and compile_call["mode"] == "exec",
        "validate_handler_has_no_exec_call": all(row["name"] != "exec" for row in validate_exec_calls),
        "validate_handler_has_no_eval_call": all(row["name"] != "eval" for row in validate_exec_calls),
        "compiled_object_not_assigned": "compiled" not in validate_source and "code_obj" not in validate_source,
        "syntax_errors_are_recorded_not_executed": "except SyntaxError as e:" in validate_source
        and '"severity": "error"' in validate_source,
        "success_partial_based_on_errors": "TaskResultStatus.SUCCESS if not errors else TaskResultStatus.PARTIAL"
        in validate_source,
        "optional_llm_validation_path_present": "chat_func = self._get_chat_function()" in validate_source
        and "user_message=prompt" in validate_source,
        "llm_prompt_contains_code_content_slice": "{code_content[:8000]}" in validate_source,
        "llm_path_is_analysis_not_local_execution": "Validate this {language} code for errors:" in validate_source
        and "Logical errors and potential bugs" in validate_source,
    }
    confirmed = all(source_signals.values())
    validate_handler_line = line_number(source, "def _execute_validate(")
    candidate_compile_line = line_number_after(source, 'compile(code_content, "<string>", "exec")', validate_handler_line)
    validate_chat_function_line = line_number_after(source, "chat_func = self._get_chat_function()", validate_handler_line)
    validate_llm_call_line = line_number_after(source, "response = chat_func(", validate_handler_line)

    evidence.update(
        {
            "source_locations": {
                "validate_handler_line": validate_handler_line,
                "candidate_compile_line": candidate_compile_line,
                "chat_function_line": line_number(source, "chat_func = self._get_chat_function()"),
                "validate_chat_function_line": validate_chat_function_line,
                "validate_llm_call_line": validate_llm_call_line,
            },
            "candidate_context": line_context(
                source,
                candidate_compile_line,
                radius=10,
            ),
            "llm_validation_context": line_context(source, validate_llm_call_line, radius=12),
            "exec_family_calls_in_file": exec_family_calls,
            "exec_family_calls_in_validate_handler": validate_exec_calls,
            "source_signals": source_signals,
            "local_code_executed": False,
            "llm_service_called": False,
            "network_used": False,
            "file_write_performed": False,
            "shell_executed": False,
            "not_a_vulnerability_claim": confirmed,
            "status": "confirmed_guarded_compile_only_validation_with_optional_llm_review_boundary"
            if confirmed
            else "compile_only_validation_boundary_not_confirmed",
            "claim_boundary": {
                "classification": (
                    "guarded compile-only syntax validation path with optional LLM review; "
                    "not vulnerability-level local code execution"
                ),
                "why_not_cve_ready": [
                    "The candidate uses compile(..., 'exec') for Python syntax validation.",
                    "The validation handler does not call exec() or eval() on the compiled code.",
                    "A probe containing a raise statement was previously accepted as syntactically valid without execution.",
                    "The optional chat_func path sends a validation prompt for analysis; it is not local code execution.",
                    "No shell command, file write, unauthenticated remote boundary, or demonstrated impact primitive is established.",
                ],
                "residual_security_semantics": [
                    "Code content may be included in an LLM validation prompt when an internal chat function is available.",
                    "That residual issue should be modeled as external LLM/data-flow semantics, not as dynamic local code execution.",
                ],
                "paper_use": (
                    "negative-control / semantic-disambiguation case showing that Security-ADG should distinguish "
                    "compile-only syntax checks and LLM review from actual code execution"
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
