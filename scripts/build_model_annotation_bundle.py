"""Build blinded, frozen-source inputs for independent model annotation."""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
TASKS = BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl"
MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
OUTPUT_DIR = BASE_DIR / "annotations" / "model_annotation" / "inputs"
OUTPUT_JSONL = OUTPUT_DIR / "model_tasks_blinded.jsonl"
BY_TASK_DIR = OUTPUT_DIR / "by_task"
PACKAGE_DIR = BASE_DIR / "annotations" / "model_annotation"
PACKAGE_MANIFEST = PACKAGE_DIR / "bundle_manifest.json"
FULL_FILE_MAX_LINES = 400
FULL_FILE_MAX_CHARS = 30_000
WINDOW_LINES = 80


def frozen_file(repository: Path, commit: str, path: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={repository.as_posix()}",
            "-C",
            str(repository),
            "show",
            f"{commit}:{path}",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.decode("utf-8", errors="replace")


def build_input(task: dict, manifest_row: dict) -> dict:
    repository = (BASE_DIR / manifest_row["repository_path"]).resolve()
    source = frozen_file(repository, task["git_commit"], task["file"])
    source_lines = source.splitlines()
    evidence = task["evidence_lines"]
    if len(source_lines) <= FULL_FILE_MAX_LINES and len(source) <= FULL_FILE_MAX_CHARS:
        start, end, scope = 1, len(source_lines), "full_file"
    else:
        start = max(1, min(evidence) - WINDOW_LINES)
        end = min(len(source_lines), max(evidence) + WINDOW_LINES)
        scope = "evidence_window"
    numbered = "\n".join(
        f"{number:6d} | {source_lines[number - 1]}" for number in range(start, end + 1)
    )
    record = {
        "task_id": task["task_id"],
        "candidate_id": task["candidate_id"],
        "repository": task["repo"],
        "git_commit": task["git_commit"],
        "file": task["file"],
        "symbol": task["symbol"],
        "candidate_behavior": task["candidate_behavior"],
        "evidence_lines": evidence,
        "evidence_line_sha256": task["evidence_line_sha256"],
        "context_scope": scope,
        "context_start_line": start,
        "context_end_line": end,
        "file_line_count": len(source_lines),
        "context_truncated": scope != "full_file",
        "source_file_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "source_context": numbered,
    }
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    record["input_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return record


def main() -> int:
    with TASKS.open("r", encoding="utf-8") as handle:
        tasks = [json.loads(line) for line in handle if line.strip()]
    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest = {row["repo"]: row for row in csv.DictReader(handle)}

    records = [build_input(task, manifest[task["repo"]]) for task in tasks]
    assert len(records) == 150
    assert len({record["task_id"] for record in records}) == 150
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    BY_TASK_DIR.mkdir(parents=True, exist_ok=True)

    temporary = OUTPUT_JSONL.with_suffix(OUTPUT_JSONL.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    temporary.replace(OUTPUT_JSONL)

    for record in records:
        destination = BY_TASK_DIR / f"{record['task_id']}.json"
        destination.write_text(
            json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    package_files = [
        PACKAGE_DIR / "system_prompt.md",
        PACKAGE_DIR / "model_annotation_guide.md",
        PACKAGE_DIR / "user_prompt_template.md",
        PACKAGE_DIR / "output_schema.json",
        OUTPUT_JSONL,
    ]
    package_manifest = {
        "protocol_version": "hybrid-model-panel-v3",
        "task_count": len(records),
        "full_file_contexts": sum(r["context_scope"] == "full_file" for r in records),
        "windowed_contexts": sum(r["context_scope"] == "evidence_window" for r in records),
        "files": {
            path.relative_to(BASE_DIR).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in package_files
        },
    }
    PACKAGE_MANIFEST.write_text(
        json.dumps(package_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(f"Blinded model inputs: {len(records)}")
    print(f"Full-file contexts: {sum(r['context_scope'] == 'full_file' for r in records)}")
    print(f"Windowed contexts: {sum(r['context_scope'] == 'evidence_window' for r in records)}")
    print(f"JSONL: {OUTPUT_JSONL}")
    print(f"Per-task files: {BY_TASK_DIR}")
    print(f"Package manifest: {PACKAGE_MANIFEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
