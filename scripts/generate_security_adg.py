"""Generate label-independent Security-ADG candidates from frozen pilot commits.

The generator is intentionally conservative: it never executes repository code,
never consumes model/human labels, and marks all inferred dependencies as
``heuristic_candidate``.  By default only development repositories are used.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import subprocess
import tarfile
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
DEFAULT_FINDINGS = BASE_DIR / "analysis" / "raw_findings.jsonl"
DEFAULT_OUTPUT = BASE_DIR / "graphs" / "security_adg" / "development.jsonl"
DEFAULT_SUMMARY = BASE_DIR / "graphs" / "security_adg" / "development_summary.json"
GENERATOR_VERSION = "security_adg_heuristic_v1"

SOURCE_HINTS = {
    "request_or_message": re.compile(
        r"\b(request|req|message|prompt|action|command|url|query|input|payload|arguments?|params?)\b",
        re.IGNORECASE,
    ),
    "environment": re.compile(r"\b(?:os\.getenv|os\.environ|process\.env)\b"),
    "file_or_network": re.compile(
        r"\b(?:readFile|read_text|read_bytes|\.read\s*\(|fetch\s*\(|requests\.|httpx\.|response\.)",
        re.IGNORECASE,
    ),
}
GUARD_HINT = re.compile(
    r"^\s*(?:if\b|assert\b|raise\b|throw\b)|\b(?:validate|sanitize|allowlist|denylist|permission|authorize|confirm)\b",
    re.IGNORECASE,
)
CALL_HINT = re.compile(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
PARAMETER_HINT = re.compile(
    r"(?:\bdef\s+[A-Za-z_]\w*|\b(?:async\s+)?[A-Za-z_$][\w$]*)\s*\(([^)]*)\)"
)

EFFECT_BY_CATEGORY = {
    "browser_control": "browser_state_or_remote_content",
    "command_execution": "process_or_shell",
    "credential_access": "credential_material",
    "database_access": "persistent_database",
    "dynamic_code_execution": "runtime_interpreter",
    "external_tool_invocation": "external_tool_or_agent",
    "filesystem_delete": "persistent_filesystem",
    "filesystem_read": "filesystem_confidentiality",
    "filesystem_write": "persistent_filesystem",
    "message_or_email_send": "external_recipient",
    "network_access": "remote_network",
    "permission_or_auth_change": "authorization_state",
}


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def frozen_file(repo_path: Path, commit: str, relative_path: str) -> str:
    command = [
        "git",
        "-c",
        f"safe.directory={repo_path.as_posix()}",
        "-C",
        str(repo_path),
        "show",
        f"{commit}:{relative_path}",
    ]
    result = subprocess.run(command, capture_output=True, check=False)
    if result.returncode:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git show failed for {relative_path}: {error}")
    return result.stdout.decode("utf-8", errors="replace")


def frozen_files(repo_path: Path, commit: str, relative_paths: set[str]) -> dict[str, str]:
    """Read a set of files from one pinned tree using a single Git invocation."""
    command = [
        "git", "-c", f"safe.directory={repo_path.as_posix()}", "-C", str(repo_path),
        "archive", "--format=tar", commit,
    ]
    result = subprocess.run(command, capture_output=True, check=False)
    if result.returncode:
        # Some frozen trees include a Windows-incompatible non-source path
        # (e.g. an NTFS Zone.Identifier stream).  Archive then fails before
        # it can return requested source blobs.  Read only the explicit,
        # already-selected source paths instead; nothing is checked out.
        loaded = {}
        failures = []
        for relative_path in relative_paths:
            try:
                loaded[relative_path.replace("\\", "/")] = frozen_file(repo_path, commit, relative_path)
            except RuntimeError as exc:
                failures.append(str(exc))
        if failures:
            error = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"git archive failed for {repo_path}: {error}; "
                f"fallback git show failed: {failures[:2]}"
            )
        return loaded
    wanted = {path.replace("\\", "/") for path in relative_paths}
    loaded: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        for member in archive:
            if member.name not in wanted or not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is not None:
                loaded[member.name] = extracted.read().decode("utf-8", errors="replace")
    missing = sorted(wanted - loaded.keys())
    if missing:
        raise RuntimeError(f"archive omitted {len(missing)} requested source files, e.g. {missing[:3]}")
    return loaded


def bounded_context(lines: list[str], evidence_lines: list[int], radius: int) -> tuple[int, int, list[str]]:
    start = max(1, min(evidence_lines) - radius)
    end = min(len(lines), max(evidence_lines) + radius)
    return start, end, lines[start - 1 : end]


def add_node(nodes: list[dict], node_type: str, **attributes) -> str:
    node_id = f"n{len(nodes) + 1}"
    nodes.append({"id": node_id, "type": node_type, **attributes})
    return node_id


def source_candidates(context: list[str], context_start: int) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, int]] = set()
    for offset, line in enumerate(context):
        line_number = context_start + offset
        parameter_match = PARAMETER_HINT.search(line)
        if parameter_match:
            parameters = parameter_match.group(1).strip()
            meaningful = [
                item.strip()
                for item in parameters.split(",")
                if item.strip() and item.strip() not in {"self", "this", "*", "/"}
            ]
            if meaningful:
                found.append(
                    {
                        "source_type": "function_parameter",
                        "line": line_number,
                        "snippet": line.strip()[:300],
                        "symbols": meaningful[:12],
                        "trust": "less_trusted_or_unknown",
                    }
                )
        for source_type, pattern in SOURCE_HINTS.items():
            if pattern.search(line):
                key = (source_type, line_number)
                if key not in seen:
                    seen.add(key)
                    found.append(
                        {
                            "source_type": source_type,
                            "line": line_number,
                            "snippet": line.strip()[:300],
                            "trust": "less_trusted_or_unknown",
                        }
                    )
    return found[:8]


def guard_candidates(context: list[str], context_start: int, first_evidence: int) -> list[dict]:
    return [
        {"line": context_start + offset, "snippet": line.strip()[:300]}
        for offset, line in enumerate(context)
        if first_evidence - 12 <= context_start + offset <= first_evidence
        and GUARD_HINT.search(line)
    ][:8]


def operation_name(lines: list[str], evidence_lines: list[int], detector: str) -> str:
    for line_number in evidence_lines:
        if 1 <= line_number <= len(lines):
            matches = CALL_HINT.findall(lines[line_number - 1])
            if matches:
                return matches[-1]
    return detector.split(";")[0]


def make_graph(finding: dict, manifest_row: dict, text: str, radius: int) -> dict:
    lines = text.splitlines()
    evidence_lines = [int(value) for value in finding["evidence_lines"]]
    context_start, context_end, context = bounded_context(lines, evidence_lines, radius)
    verified = []
    expected = list(finding.get("evidence_line_sha256", []))
    for index, line_number in enumerate(evidence_lines):
        actual = hashlib.sha256(lines[line_number - 1].strip().encode("utf-8")).hexdigest()
        verified.append(index < len(expected) and actual == expected[index])
    if not all(verified):
        raise RuntimeError(f"evidence hash mismatch: {finding['annotation_id']}")

    nodes: list[dict] = []
    edges: list[dict] = []
    symbol = add_node(
        nodes,
        "agent_or_program_symbol",
        name=finding["symbol"],
        agent_relevance="unknown_pending_annotation",
    )
    operation = add_node(
        nodes,
        "security_sensitive_operation",
        name=operation_name(lines, evidence_lines, finding["detector"]),
        category=finding["category"],
        detector=finding["detector"],
        evidence_lines=evidence_lines,
        confidence=finding["confidence"],
    )
    effect = add_node(
        nodes,
        "external_effect",
        target_class=EFFECT_BY_CATEGORY.get(finding["category"], "external_or_persistent_state"),
        effect_confirmation="unknown_pending_annotation",
    )
    edges.extend(
        [
            {"from": symbol, "to": operation, "type": "contains"},
            {"from": operation, "to": effect, "type": "may_cause", "status": "category_semantics"},
        ]
    )

    source_ids = []
    for source in source_candidates(context, context_start):
        source_id = add_node(nodes, "input_source", **source)
        source_ids.append(source_id)
        edges.append(
            {
                "from": source_id,
                "to": operation,
                "type": "may_data_depend_on",
                "status": "heuristic_candidate",
            }
        )
    guard_ids = []
    for guard in guard_candidates(context, context_start, min(evidence_lines)):
        guard_id = add_node(nodes, "guard_candidate", **guard, effectiveness="unknown_pending_annotation")
        guard_ids.append(guard_id)
        edges.append(
            {
                "from": guard_id,
                "to": operation,
                "type": "may_guard",
                "status": "heuristic_candidate",
            }
        )
    boundary = add_node(
        nodes,
        "trust_boundary",
        boundary="less_trusted_input_to_security_sensitive_effect",
        crossed="unknown_pending_annotation",
    )
    for source_id in source_ids:
        edges.append(
            {
                "from": source_id,
                "to": boundary,
                "type": "may_cross",
                "status": "heuristic_candidate",
            }
        )
    edges.append({"from": boundary, "to": operation, "type": "reaches"})

    return {
        "schema_version": "1.0.0",
        "generator": GENERATOR_VERSION,
        "graph_id": f"SADG-{finding['annotation_id']}",
        "candidate_id": finding["annotation_id"],
        "provenance": {
            "sample_id": finding["sample_id"],
            "repo": finding["repo"],
            "commit": finding["git_commit"],
            "file": finding["file"],
            "experiment_split": manifest_row.get("experiment_split", "all_corpus"),
            "use_for_method_tuning": manifest_row.get("use_for_method_tuning", "false").lower() == "true",
            "label_inputs_used": False,
            "source_execution_used": False,
            "evidence_hash_verified": all(verified),
        },
        "context": {
            "line_start": context_start,
            "line_end": context_end,
            "sha256": hashlib.sha256("\n".join(context).encode("utf-8")).hexdigest(),
        },
        "nodes": nodes,
        "edges": edges,
        "views": {
            "sink_only": {"nodes": [operation], "edges": []},
            "plain_adg": {"nodes": [symbol, operation, effect], "edges": ["contains", "may_cause"]},
            "security_adg": {
                "nodes": [node["id"] for node in nodes],
                "edges": [edge["type"] for edge in edges],
                "source_candidates": len(source_ids),
                "guard_candidates": len(guard_ids),
            },
        },
    }


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--split", default="development", choices=("development", "held_out_evaluation", "all"))
    parser.add_argument("--context-radius", type=int, default=20)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.context_radius < 1 or args.context_radius > 100:
        raise SystemExit("--context-radius must be between 1 and 100")
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest = list(csv.DictReader(handle))
    manifest_by_repo = {row["repo"]: row for row in manifest}
    findings = read_jsonl(args.findings)
    selected = [
        finding
        for finding in findings
        if args.split == "all" or manifest_by_repo[finding["repo"]]["experiment_split"] == args.split
    ]
    cache: dict[tuple[str, str], str] = {}
    graphs = []
    for finding in selected:
        row = manifest_by_repo[finding["repo"]]
        key = (finding["repo"], finding["file"])
        if key not in cache:
            repo_path = (BASE_DIR / row["repository_path"]).resolve()
            cache[key] = frozen_file(repo_path, finding["git_commit"], finding["file"])
        graphs.append(make_graph(finding, row, cache[key], args.context_radius))
    write_jsonl(args.output, graphs)

    categories = Counter(graph["nodes"][1]["category"] for graph in graphs)
    summary = {
        "schema_version": "1.0.0",
        "generator": GENERATOR_VERSION,
        "split": args.split,
        "graph_count": len(graphs),
        "repository_count": len({graph["provenance"]["repo"] for graph in graphs}),
        "source_file_count": len(cache),
        "category_counts": dict(sorted(categories.items())),
        "graphs_with_source_candidates": sum(
            graph["views"]["security_adg"]["source_candidates"] > 0 for graph in graphs
        ),
        "graphs_with_guard_candidates": sum(
            graph["views"]["security_adg"]["guard_candidates"] > 0 for graph in graphs
        ),
        "label_inputs_used": False,
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
