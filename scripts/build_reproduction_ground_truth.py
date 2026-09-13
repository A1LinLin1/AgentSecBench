"""Build reproduction-confirmed ground truth from local evidence records.

The resulting dataset deliberately separates:

* behavior_ground_truth: a security-relevant behavior/path was reproduced or
  source/runtime-confirmed without using human/model labels.
* vulnerability_ground_truth: a stricter subset with both impact evidence and a
  confirmed trust/auth boundary.  This is intentionally conservative.

Single-reviewer adjudication files are not inputs to this script.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "ground_truth" / "reproduction_confirmed_gt.jsonl"
DEFAULT_SUMMARY = BASE_DIR / "analysis" / "ground_truth" / "reproduction_confirmed_gt_summary.json"
DEFAULT_INPUT_DIRS = [
    BASE_DIR / "analysis" / "agent_discovery" / "reproduction_readiness",
    BASE_DIR / "analysis" / "reproduction" / "heldout",
]


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def evidence_id(path: Path, record: dict) -> str:
    return (
        record.get("reproduction_id")
        or record.get("scouting_id")
        or record.get("task_id")
        or path.name.replace(".latest.json", "")
    )


def case_id(path: Path, record: dict) -> str:
    if record.get("reproduction_id"):
        return record["reproduction_id"]
    if record.get("scouting_id"):
        return record["scouting_id"]
    if record.get("task_id"):
        return record["task_id"]
    return path.name.replace(".latest.json", "")


def infer_behavior_category(record: dict) -> str:
    text = " ".join(
        str(record.get(key, ""))
        for key in ("status", "operation", "candidate_file", "claim_boundary")
    ).lower()
    dynamic_patterns = (
        r"\bexec\s*\(",
        r"\beval\s*\(",
        r"\bcompile\s*\(",
        r"\binterpreter\b",
        r"\bcode_metric\b",
        r"\bcode execution\b",
        r"\bdynamic code\b",
    )
    if any(re.search(pattern, text) for pattern in dynamic_patterns):
        return "dynamic_code_execution"
    if any(token in text for token in ("shell", "subprocess", "powershell", "spawn", "command", "process")):
        return "command_execution"
    if any(token in text for token in ("network", "http", "fetch", "socket", "ping")):
        return "network_access"
    if any(token in text for token in ("write", "markdown", "scratch file")):
        return "filesystem_write"
    if any(token in text for token in ("tar", "extract")):
        return "archive_extraction"
    if any(token in text for token in ("clipboard", "tool_parameter", "mcp_tool", "agent_tool")):
        return "external_tool_invocation"
    return "security_sensitive_behavior"


def infer_proof_types(record: dict) -> list[str]:
    status = str(record.get("status", "")).lower()
    proof_types: set[str] = set()
    if record.get("marker_seen") or "marker" in json.dumps(record, ensure_ascii=False).lower():
        proof_types.add("runtime_marker")
    if record.get("runtime_monkeypatch_observation") or record.get("captured_subprocess_calls"):
        proof_types.add("runtime_stub_or_monkeypatch")
    if (
        record.get("source_signals")
        or record.get("candidate_context")
        or record.get("unexecuted_construction_proof")
        or record.get("readme_signals")
        or record.get("workflow_records")
    ):
        proof_types.add("source_trace")
    if any(token in status for token in ("boundary", "unauthenticated", "reachability", "documented_cli", "documented_workflow")):
        proof_types.add("boundary_or_reachability")
    if any(token in status for token in ("confirmed_local", "confirmed_runtime", "confirmed_mcp")):
        proof_types.add("local_reproduction")
    if not proof_types:
        proof_types.add("confirmed_record")
    return sorted(proof_types)


def has_impact_evidence(records: list[dict]) -> bool:
    joined = " ".join(str(row.get("status", "")) + " " + str(row.get("operation", "")) for row in records).lower()
    if any(row.get("marker_seen") for row in records):
        return True
    return any(
        token in joined
        for token in (
            "code execution",
            "local_code",
            "interpreter_execution",
            "codeprompt_exec",
            "powershell",
            "shell_true",
            "subprocess",
            "spawn_path",
        )
    )


def has_confirmed_boundary(records: list[dict]) -> bool:
    joined = " ".join(str(row.get("status", "")) for row in records).lower()
    if "unauthenticated" in joined:
        return True
    # Reachability alone is useful behavior evidence, but not enough for a
    # vulnerability ground truth claim unless paired with a concrete boundary.
    return "auth_material_supplied" in joined and "false" in joined and "boundary" in joined


def explicit_not_vulnerability(records: list[dict]) -> bool:
    for row in records:
        if bool(row.get("not_a_vulnerability_claim")):
            return True
        claim_boundary = row.get("claim_boundary")
        if isinstance(claim_boundary, dict) and bool(claim_boundary.get("not_a_vulnerability_claim")):
            return True
    return False


def vulnerability_ground_truth(records: list[dict]) -> tuple[bool, str]:
    if explicit_not_vulnerability(records):
        return False, "explicit_not_a_vulnerability_claim"
    if has_confirmed_boundary(records) and has_impact_evidence(records):
        return True, "confirmed_boundary_and_impact_reproduction"
    return False, "behavior_confirmed_but_vulnerability_boundary_not_confirmed"


def infer_operation_line(records: list[dict]) -> tuple[int | None, str | None]:
    """Prefer a reproduced sink/call line over a wrapper function line.

    Many reproduction records store candidate_line as the public function or
    tool entrypoint while also recording an AST-observed effectful call such as
    subprocess_run_call_ast.line.  For graph construction, the effectful call
    line is the better evidence coordinate.
    """
    high_priority_tokens = ("subprocess", "spawn", "exec", "eval", "ps_helper")
    candidates: list[tuple[int, int, str]] = []
    for record in records:
        for key, value in record.items():
            if not isinstance(value, dict) or "line" not in value:
                continue
            try:
                line = int(value["line"])
            except (TypeError, ValueError):
                continue
            key_lower = key.lower()
            priority = 0 if any(token in key_lower for token in high_priority_tokens) else 1
            candidates.append((priority, line, key))
    if not candidates:
        return None, None
    priority, line, key = min(candidates, key=lambda item: (item[0], item[1]))
    return line, key


def infer_candidate_coordinate(records: list[dict]) -> tuple[str | None, int | None, str | None]:
    """Find the best representative file/line coordinate for a GT case."""
    for record in records:
        if record.get("candidate_file") and record.get("candidate_line") not in (None, ""):
            return record["candidate_file"], int(record["candidate_line"]), "candidate_file_and_line"
    for record in records:
        files = record.get("candidate_files")
        lines = record.get("candidate_lines")
        if isinstance(files, list) and files and isinstance(lines, list) and lines:
            return str(files[0]), int(lines[0]), "representative_from_candidate_files_and_lines"
    return None, None, None


def load_evidence(input_dirs: list[Path]) -> list[tuple[Path, dict]]:
    evidence: list[tuple[Path, dict]] = []
    for directory in input_dirs:
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.latest.json")):
            record = read_json(path)
            status = str(record.get("status", ""))
            if not status.startswith("confirmed_") and "confirmed" not in status:
                continue
            if record.get("human_labels_used") is True or record.get("model_labels_used") is True:
                continue
            evidence.append((path, record))
    return evidence


def build_ground_truth(evidence: list[tuple[Path, dict]]) -> list[dict]:
    grouped: dict[str, list[tuple[Path, dict]]] = defaultdict(list)
    for path, record in evidence:
        grouped[case_id(path, record)].append((path, record))

    rows: list[dict] = []
    for gid in sorted(grouped):
        items = grouped[gid]
        records = [record for _path, record in items]
        primary = records[0]
        vuln_gt, vuln_basis = vulnerability_ground_truth(records)
        operation_line, operation_line_source = infer_operation_line(records)
        candidate_file, candidate_line, candidate_coordinate_source = infer_candidate_coordinate(records)
        proof_types = sorted({proof for record in records for proof in infer_proof_types(record)})
        statuses = sorted({record.get("status", "") for record in records})
        evidence_files = [str(path.relative_to(BASE_DIR)) for path, _record in items]
        rows.append(
            {
                "gt_id": gid,
                "repository": primary.get("repository") or primary.get("repo"),
                "frozen_commit": primary.get("frozen_commit") or primary.get("commit"),
                "candidate_file": candidate_file,
                "candidate_line": candidate_line,
                "candidate_coordinate_source": candidate_coordinate_source,
                "evidence_operation_line": operation_line,
                "evidence_operation_line_source": operation_line_source,
                "behavior_category": infer_behavior_category(primary),
                "behavior_ground_truth": True,
                "vulnerability_ground_truth": vuln_gt,
                "vulnerability_ground_truth_basis": vuln_basis,
                "proof_types": proof_types,
                "statuses": statuses,
                "evidence_files": evidence_files,
                "auth_material_supplied": any(record.get("auth_material_supplied") is True for record in records),
                "not_a_vulnerability_claim": explicit_not_vulnerability(records),
                "human_labels_used": False,
                "model_labels_used": False,
                "claim_boundary": (
                    "reproduction-confirmed security behavior; vulnerability claim only when "
                    "vulnerability_ground_truth is true"
                ),
            }
        )
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def summarize(rows: list[dict], input_dirs: list[Path], output: Path) -> dict:
    categories = Counter(row["behavior_category"] for row in rows)
    proof_types = Counter(proof for row in rows for proof in row["proof_types"])
    return {
        "status": "completed",
        "schema_version": "1.0",
        "input_dirs": [str(path) for path in input_dirs],
        "output": str(output),
        "case_count": len(rows),
        "behavior_ground_truth_count": sum(row["behavior_ground_truth"] for row in rows),
        "vulnerability_ground_truth_count": sum(row["vulnerability_ground_truth"] for row in rows),
        "not_vulnerability_claim_count": sum(row["not_a_vulnerability_claim"] for row in rows),
        "repositories": len({row["repository"] for row in rows}),
        "behavior_categories": dict(sorted(categories.items())),
        "proof_types": dict(sorted(proof_types.items())),
        "label_inputs_used": False,
        "human_reviewed_sample_used": False,
        "model_labels_used": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, action="append", default=None)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    args = parser.parse_args()
    input_dirs = args.input_dir or DEFAULT_INPUT_DIRS
    rows = build_ground_truth(load_evidence(input_dirs))
    write_jsonl(args.output, rows)
    summary = summarize(rows, input_dirs, args.output)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
