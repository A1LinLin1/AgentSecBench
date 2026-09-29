"""Mine real frozen-corpus examples for dependency-analysis challenge patterns.

This script is read-only with respect to the corpus. It scans frozen Git
objects listed in dataset/corpus_manifest.csv, looks for Python functions where
subprocess-like operations interact with parameter flow in ways that the
development probe exposed as difficult, and records source-backed candidates.

The output is a development evidence inventory, not vulnerability evidence and
not a held-out benchmark.
"""

from __future__ import annotations

import argparse
import ast
import csv
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Iterable

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "scripts"))
from security_adg_dataflow import analyze_python, loaded_names


SINKS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "os.popen",
}


@dataclass(frozen=True)
class RepoRow:
    sample_id: str
    repo: str
    path: Path
    commit: str


def sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def call_name(node: ast.AST) -> str:
    if not isinstance(node, ast.Call):
        return ""
    return dotted_name(node.func)


def is_sink_call(node: ast.AST) -> bool:
    name = call_name(node)
    return name in SINKS or name.endswith(".run_command") or name.endswith(".execute_command")


def function_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    args = node.args
    params = {
        item.arg
        for item in [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if item.arg not in {"self", "cls"}
    }
    if args.vararg:
        params.add(args.vararg.arg)
    if args.kwarg:
        params.add(args.kwarg.arg)
    return params


def assigned_name(target: ast.AST) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    return None


def assignment_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Assign):
        result: set[str] = set()
        for target in node.targets:
            name = assigned_name(target)
            if name:
                result.add(name)
        return result
    if isinstance(node, ast.AnnAssign):
        name = assigned_name(node.target)
        return {name} if name else set()
    return set()


def assignment_value(node: ast.AST) -> ast.AST | None:
    if isinstance(node, ast.Assign):
        return node.value
    if isinstance(node, ast.AnnAssign):
        return node.value
    return None


def iter_functions(tree: ast.AST) -> Iterable[ast.FunctionDef | ast.AsyncFunctionDef]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def iter_assignments_before(scope: ast.AST, line: int) -> Iterable[ast.Assign | ast.AnnAssign]:
    for node in ast.walk(scope):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and getattr(node, "lineno", line) < line:
            yield node


def sink_argument_names(call: ast.Call) -> set[str]:
    names: set[str] = set()
    for item in [*call.args, *(kw.value for kw in call.keywords)]:
        names.update(loaded_names(item))
    return names


def direct_name_loads(call: ast.Call) -> set[str]:
    names: set[str] = set()
    for item in [*call.args, *(kw.value for kw in call.keywords)]:
        if isinstance(item, ast.Name):
            names.add(item.id)
    return names


def literal_key(node: ast.AST) -> str | int | float | bool | None:
    if isinstance(node, ast.Constant):
        return node.value
    return None


def subscript_literal_uses(node: ast.AST) -> list[tuple[str, object]]:
    uses: list[tuple[str, object]] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Subscript) and isinstance(child.value, ast.Name):
            key = literal_key(child.slice)
            if key is not None:
                uses.append((child.value.id, key))
    return uses


def source_context(lines: list[str], line: int, radius: int) -> list[str]:
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return [f"{number}: {lines[number - 1]}" for number in range(start, end + 1)]


def engine_prediction(source: str, line: int, symbol: str) -> dict:
    result = analyze_python(
        source,
        [line],
        symbol=symbol,
        prefer_parameter_sources=True,
        respect_parameter_overwrites=True,
        include_intrinsic_source_operation=False,
    )
    return {
        "prediction": bool(result.sources and result.dependency_paths),
        "analysis": asdict(result),
    }


def build_record(
    repo: RepoRow,
    file_path: str,
    source: str,
    scope: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
    mechanism: str,
    details: dict,
    radius: int,
) -> dict:
    lines = source.splitlines()
    return {
        "candidate_id": "",
        "mechanism": mechanism,
        "sample_id": repo.sample_id,
        "repo": repo.repo,
        "commit": repo.commit,
        "file": file_path,
        "function": scope.name,
        "function_line": scope.lineno,
        "sink_line": call.lineno,
        "sink": call_name(call),
        "details": details,
        "source_sha256": sha_text(source),
        "context": source_context(lines, call.lineno, radius),
        "engine_current_worktree_v2_4_flags": engine_prediction(source, call.lineno, scope.name),
        "claim_boundary": "real frozen source pattern candidate; not a runtime proof, exploitability claim, or held-out label",
    }


def find_copy_before_overwrite(
    repo: RepoRow,
    file_path: str,
    source: str,
    scope: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
    radius: int,
) -> list[dict]:
    params = function_params(scope)
    sink_names = direct_name_loads(call)
    records = []
    assignments = list(iter_assignments_before(scope, call.lineno))
    for first in assignments:
        first_value = assignment_value(first)
        if not isinstance(first_value, ast.Name) or first_value.id not in params:
            continue
        for alias in assignment_names(first):
            if alias not in sink_names or alias == first_value.id:
                continue
            overwrite_lines = [
                later.lineno
                for later in assignments
                if first.lineno < later.lineno < call.lineno and first_value.id in assignment_names(later)
            ]
            if not overwrite_lines:
                continue
            records.append(build_record(repo, file_path, source, scope, call, "copy_before_overwrite", {
                "source_parameter": first_value.id,
                "alias": alias,
                "alias_assignment_line": first.lineno,
                "parameter_overwrite_lines_before_sink": overwrite_lines,
            }, radius))
    return records


def if_assigns_param(node: ast.If, params: set[str]) -> list[dict]:
    hits = []
    for branch_name, statements in (("body", node.body), ("orelse", node.orelse)):
        for stmt in statements:
            for child in ast.walk(stmt):
                names = assignment_names(child)
                for name in sorted(names & params):
                    hits.append({"branch": branch_name, "parameter": name, "line": child.lineno})
    return hits


def find_conditional_overwrite(
    repo: RepoRow,
    file_path: str,
    source: str,
    scope: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
    radius: int,
) -> list[dict]:
    params = function_params(scope)
    sink_names = direct_name_loads(call)
    records = []
    for node in ast.walk(scope):
        if not isinstance(node, ast.If) or node.lineno >= call.lineno:
            continue
        hits = [hit for hit in if_assigns_param(node, params) if hit["parameter"] in sink_names and hit["line"] < call.lineno]
        if hits:
            records.append(build_record(repo, file_path, source, scope, call, "conditional_parameter_overwrite", {
                "if_line": node.lineno,
                "test_source": ast.get_source_segment(source, node.test),
                "overwrites": hits,
            }, radius))
    return records


def find_field_insensitive_container(
    repo: RepoRow,
    file_path: str,
    source: str,
    scope: ast.FunctionDef | ast.AsyncFunctionDef,
    call: ast.Call,
    radius: int,
) -> list[dict]:
    params = function_params(scope)
    records = []
    dict_defs: dict[str, tuple[ast.Dict, int]] = {}
    for assignment in iter_assignments_before(scope, call.lineno):
        value = assignment_value(assignment)
        if not isinstance(value, ast.Dict):
            continue
        for name in assignment_names(assignment):
            dict_defs[name] = (value, assignment.lineno)
    for argument in [*call.args, *(kw.value for kw in call.keywords)]:
        for container, key in subscript_literal_uses(argument):
            if container not in dict_defs:
                continue
            dict_node, line = dict_defs[container]
            entries = dict(zip([literal_key(key_node) for key_node in dict_node.keys], dict_node.values))
            if key not in entries:
                continue
            selected = entries[key]
            selected_names = loaded_names(selected)
            other_sources = []
            for other_key, other_value in entries.items():
                if other_key == key:
                    continue
                loaded = sorted(loaded_names(other_value) & params)
                if loaded:
                    other_sources.append({"key": other_key, "parameters": loaded})
            if other_sources and not (selected_names & params):
                records.append(build_record(repo, file_path, source, scope, call, "field_insensitive_container", {
                    "container": container,
                    "dict_assignment_line": line,
                    "selected_key": key,
                    "selected_source": ast.get_source_segment(source, selected),
                    "other_parameter_backed_keys": other_sources,
                }, radius))
    return records


def find_records(repo: RepoRow, file_path: str, source: str, radius: int) -> tuple[list[dict], str | None]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [], f"parse_error:{exc.msg}"
    records: list[dict] = []
    for scope in iter_functions(tree):
        params = function_params(scope)
        if not params:
            continue
        for node in ast.walk(scope):
            if not isinstance(node, ast.Call) or not is_sink_call(node):
                continue
            records.extend(find_copy_before_overwrite(repo, file_path, source, scope, node, radius))
            records.extend(find_conditional_overwrite(repo, file_path, source, scope, node, radius))
            records.extend(find_field_insensitive_container(repo, file_path, source, scope, node, radius))
    return records, None


def run_git(repo_path: Path, args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo_path), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )


def frozen_python_files(repo: RepoRow) -> tuple[list[str], str | None]:
    result = run_git(repo.path, ["ls-tree", "-r", "--name-only", repo.commit])
    if result.returncode != 0:
        return [], result.stderr.decode("utf-8", errors="replace").strip()
    return [
        line for line in result.stdout.decode("utf-8", errors="replace").splitlines()
        if line.endswith(".py")
    ], None


def frozen_file_text(repo: RepoRow, file_path: str) -> tuple[str | None, str | None]:
    result = run_git(repo.path, ["show", f"{repo.commit}:{file_path}"])
    if result.returncode != 0:
        return None, result.stderr.decode("utf-8", errors="replace").strip()
    return result.stdout.decode("utf-8", errors="replace"), None


def load_manifest(path: Path, repo_filter: set[str] | None) -> list[RepoRow]:
    rows: list[RepoRow] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            repo = row["repo"]
            if repo_filter and repo not in repo_filter and row["sample_id"] not in repo_filter:
                continue
            rows.append(RepoRow(row["sample_id"], repo, BASE / row["repository_path"], row["git_commit"]))
    return rows


def assign_ids(records: list[dict]) -> None:
    for index, record in enumerate(records, start=1):
        record["candidate_id"] = f"DCC-{index:04d}"


def metric_counts(records: list[dict]) -> dict:
    by_mechanism: dict[str, int] = {}
    by_repo: dict[str, int] = {}
    engine_positive = 0
    for record in records:
        by_mechanism[record["mechanism"]] = by_mechanism.get(record["mechanism"], 0) + 1
        by_repo[record["repo"]] = by_repo.get(record["repo"], 0) + 1
        if record["engine_current_worktree_v2_4_flags"]["prediction"]:
            engine_positive += 1
    return {
        "records": len(records),
        "by_mechanism": dict(sorted(by_mechanism.items())),
        "by_repo": dict(sorted(by_repo.items())),
        "engine_predicted_positive": engine_positive,
        "engine_predicted_negative": len(records) - engine_positive,
    }


def write_readme(output_dir: Path, report: dict) -> None:
    counts = report["counts"]
    lines = [
        "# Dependency Challenge Case Mining",
        "",
        "Purpose: mine real frozen-corpus Python source patterns that match failure mechanisms found by the development dependency probe.",
        "",
        "This artifact is source evidence only. It is not a vulnerability report, a runtime reproduction, or a held-out benchmark.",
        "",
        f"- Repositories scanned: {report['repositories_scanned']}",
        f"- Python files scanned: {report['python_files_scanned']}",
        f"- Records: {counts['records']}",
        f"- Current engine positives: {counts['engine_predicted_positive']}",
        f"- Current engine negatives: {counts['engine_predicted_negative']}",
        "",
        "| Mechanism | Records |",
        "| --- | ---: |",
    ]
    for mechanism, count in counts["by_mechanism"].items():
        lines.append(f"| {mechanism} | {count} |")
    lines.extend([
        "",
        "| Repository | Records |",
        "| --- | ---: |",
    ])
    for repo, count in counts["by_repo"].items():
        lines.append(f"| {repo} | {count} |")
    lines.extend([
        "",
        "## Claim Boundary",
        "",
        "- Records come from frozen Git objects identified by dataset/corpus_manifest.csv.",
        "- A record means the source contains a static pattern worth developer investigation.",
        "- Runtime reachability, attacker control, exploitability, and correctness labels remain unproven.",
        "- Current-engine predictions use the current worktree implementation with v2.4-style flags and are not historical freeze claims.",
        "- The next step is to manually or instrumentally adjudicate a small subset before changing the engine.",
        "",
    ])
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=BASE / "dataset/corpus_manifest.csv")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo", action="append", default=[], help="Repo slug or sample id filter; repeatable")
    parser.add_argument("--max-per-mechanism", type=int, default=50)
    parser.add_argument("--max-files", type=int, default=0, help="Stop after this many Python files; 0 means no limit")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--progress-every", type=int, default=500)
    parser.add_argument("--context-radius", type=int, default=4)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("Choose a new output directory; existing evidence is never overwritten")
    if args.max_per_mechanism <= 0:
        parser.error("--max-per-mechanism must be positive")
    if args.context_radius < 0:
        parser.error("--context-radius must be non-negative")
    if args.max_files < 0:
        parser.error("--max-files must be non-negative")
    if args.max_file_bytes <= 0:
        parser.error("--max-file-bytes must be positive")
    if args.progress_every < 0:
        parser.error("--progress-every must be non-negative")

    repo_filter = set(args.repo) if args.repo else None
    repos = load_manifest(args.manifest, repo_filter)
    records: list[dict] = []
    skipped: list[dict] = []
    files_scanned = 0
    mechanism_counts: dict[str, int] = {}
    repos_scanned = 0

    for repo in repos:
        files, error = frozen_python_files(repo)
        if error:
            skipped.append({"repo": repo.repo, "sample_id": repo.sample_id, "reason": "git_ls_tree_failed", "detail": error})
            continue
        repos_scanned += 1
        for file_path in files:
            text, file_error = frozen_file_text(repo, file_path)
            if file_error or text is None:
                skipped.append({"repo": repo.repo, "file": file_path, "reason": "git_show_failed", "detail": file_error})
                continue
            if len(text.encode("utf-8", errors="replace")) > args.max_file_bytes:
                skipped.append({"repo": repo.repo, "file": file_path, "reason": "file_too_large"})
                continue
            files_scanned += 1
            if args.progress_every and files_scanned % args.progress_every == 0:
                print(
                    json.dumps({
                        "progress": "scanning",
                        "python_files_scanned": files_scanned,
                        "current_repo": repo.repo,
                        "records": len(records),
                    }),
                    file=sys.stderr,
                    flush=True,
                )
            found, parse_error = find_records(repo, file_path, text, args.context_radius)
            if parse_error:
                skipped.append({"repo": repo.repo, "file": file_path, "reason": parse_error})
                continue
            for record in found:
                count = mechanism_counts.get(record["mechanism"], 0)
                if count >= args.max_per_mechanism:
                    continue
                mechanism_counts[record["mechanism"]] = count + 1
                records.append(record)
            if args.max_files and files_scanned >= args.max_files:
                break
        if args.max_files and files_scanned >= args.max_files:
            break

    records.sort(key=lambda row: (row["mechanism"], row["sample_id"], row["file"], row["sink_line"]))
    assign_ids(records)
    report = {
        "purpose": "development mining of real frozen-source dependency challenge patterns",
        "created_at_note": "local run timestamp intentionally omitted; use file hashes for reproducibility",
        "manifest": str(args.manifest),
        "manifest_sha256": sha_file(args.manifest),
        "script_sha256": sha_file(Path(__file__)),
        "engine_sha256": sha_file(BASE / "scripts/security_adg_dataflow.py"),
        "python": platform.python_version(),
        "repositories_requested": len(repos),
        "repositories_scanned": repos_scanned,
        "python_files_scanned": files_scanned,
        "max_files": args.max_files,
        "max_file_bytes": args.max_file_bytes,
        "counts": metric_counts(records),
        "skipped": skipped,
        "records": records,
    }
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "dependency_challenge_cases.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    write_readme(args.output_dir, report)
    print(json.dumps({
        "output_dir": str(args.output_dir),
        "repositories_scanned": report["repositories_scanned"],
        "python_files_scanned": files_scanned,
        "counts": report["counts"],
        "skipped": len(skipped),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
