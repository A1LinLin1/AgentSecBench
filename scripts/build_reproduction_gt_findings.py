"""Convert reproduction-confirmed GT into line-localized Security-ADG findings.

This is a bridge from the reproduction-confirmed ground truth file to the graph
construction pipeline.  It uses only repository/file/line/category coordinates
already present in the reproduction evidence records; single-reviewer or model
labels are not inputs.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

try:
    from static_scan import BASE_DIR, nearest_symbol
except ModuleNotFoundError:  # pragma: no cover - package-style unit tests
    from scripts.static_scan import BASE_DIR, nearest_symbol


DEFAULT_GT = BASE_DIR / "analysis" / "ground_truth" / "reproduction_confirmed_gt.jsonl"
DEFAULT_MANIFEST = BASE_DIR / "dataset" / "corpus_manifest.csv"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "ground_truth" / "reproduction_gt_findings_v1.jsonl"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def finding_id_for_gt(gt_id: str) -> str:
    return "RGT-" + re.sub(r"[^A-Za-z0-9_-]+", "-", gt_id).strip("-")


def git_show(repo_path: Path, commit: str, file_name: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={repo_path.as_posix()}",
            "-C",
            str(repo_path),
            "show",
            f"{commit}:{file_name}",
        ],
        capture_output=True,
        check=False,
    )
    if result.returncode:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git show failed for {repo_path} {commit}:{file_name}: {stderr}")
    return result.stdout.decode("utf-8", errors="replace")


def make_finding(gt: dict, text: str, scanned_at: str) -> dict:
    line = int(gt.get("evidence_operation_line") or gt["candidate_line"])
    lines = text.splitlines()
    source_line = lines[line - 1] if 1 <= line <= len(lines) else ""
    normalized_line = source_line.strip().encode("utf-8", errors="replace")
    return {
        "annotation_id": finding_id_for_gt(gt["gt_id"]),
        "sample_id": f"RGT-{gt['gt_id']}",
        "repo": gt["repository"],
        "git_commit": gt["frozen_commit"],
        "category": gt["behavior_category"],
        "file": gt["candidate_file"],
        "line_start": line,
        "line_end": line,
        "evidence_lines": [line],
        "evidence_line_sha256": [hashlib.sha256(normalized_line).hexdigest()],
        "match_count": 1,
        "symbol": nearest_symbol(lines, line - 1) if lines else "<module>",
        "evidence": "reproduction-confirmed ground truth coordinate",
        "input_origin": "reproduction_confirmed",
        "guard": "unknown",
        "detector": "reproduction_ground_truth",
        "confidence": "confirmed",
        "review_status": "reproduction_confirmed",
        "annotator": "reproduction_gt_findings_v1",
        "notes": "Generated from reproduction-confirmed GT; no human/model labels used.",
        "scanned_at_utc": scanned_at,
        "source_gt_id": gt["gt_id"],
        "source_candidate_line": gt.get("candidate_line"),
        "source_evidence_operation_line": gt.get("evidence_operation_line"),
        "source_evidence_operation_line_source": gt.get("evidence_operation_line_source"),
        "behavior_ground_truth": bool(gt.get("behavior_ground_truth")),
        "vulnerability_ground_truth": bool(gt.get("vulnerability_ground_truth")),
    }


def build_findings(gt_rows: list[dict], manifest_rows: list[dict], base_dir: Path, scanned_at: str) -> tuple[list[dict], list[dict]]:
    manifest_by_repo = {row["repo"]: row for row in manifest_rows}
    cache: dict[tuple[str, str], str] = {}
    findings: list[dict] = []
    skipped: list[dict] = []
    for gt in sorted(gt_rows, key=lambda row: row["gt_id"]):
        if not gt.get("candidate_file") or gt.get("candidate_line") in (None, ""):
            skipped.append({"gt_id": gt["gt_id"], "reason": "missing_candidate_coordinate"})
            continue
        manifest = manifest_by_repo.get(gt["repository"])
        if manifest is None:
            skipped.append({"gt_id": gt["gt_id"], "reason": "repository_not_in_manifest", "repository": gt["repository"]})
            continue
        key = (gt["repository"], gt["candidate_file"])
        if key not in cache:
            cache[key] = git_show((base_dir / manifest["repository_path"]).resolve(), gt["frozen_commit"], gt["candidate_file"])
        findings.append(make_finding(gt, cache[key], scanned_at))
    return findings, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest_rows = list(csv.DictReader(handle))
    scanned_at = datetime.now(timezone.utc).isoformat()
    findings, skipped = build_findings(read_jsonl(args.ground_truth), manifest_rows, BASE_DIR, scanned_at)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in findings),
        encoding="utf-8",
    )
    summary = {
        "status": "completed_without_human_or_model_labels",
        "ground_truth": str(args.ground_truth),
        "output": str(args.output),
        "findings": len(findings),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "label_inputs_used": False,
        "human_reviewed_sample_used": False,
        "model_labels_used": False,
    }
    args.output.with_suffix(".summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
