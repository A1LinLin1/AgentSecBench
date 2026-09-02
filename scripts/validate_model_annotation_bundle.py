"""Validate blinded model inputs, per-task files, and package hashes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
PACKAGE_DIR = BASE_DIR / "annotations" / "model_annotation"
INPUTS = PACKAGE_DIR / "inputs" / "model_tasks_blinded.jsonl"
BY_TASK = PACKAGE_DIR / "inputs" / "by_task"
MANIFEST = PACKAGE_DIR / "bundle_manifest.json"
SCHEMA = PACKAGE_DIR / "output_schema.json"
FORBIDDEN = {
    "candidate_confidence",
    "detector",
    "experiment_split",
    "use_for_method_tuning",
    "sampling_stratum",
    "stratum_population",
    "stratum_sample_size",
    "inclusion_probability",
    "sample_weight",
    "questions",
}


def main() -> int:
    with INPUTS.open("r", encoding="utf-8") as handle:
        records = [json.loads(line) for line in handle if line.strip()]
    assert len(records) == 150
    assert len({record["task_id"] for record in records}) == 150
    assert len({record["input_sha256"] for record in records}) == 150

    for record in records:
        assert not (FORBIDDEN & set(record))
        check = dict(record)
        expected = check.pop("input_sha256")
        canonical = json.dumps(check, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == expected
        for line_number in record["evidence_lines"]:
            assert record["context_start_line"] <= line_number <= record["context_end_line"]
        per_task = json.loads((BY_TASK / f"{record['task_id']}.json").read_text(encoding="utf-8"))
        assert per_task == record

    assert len(list(BY_TASK.glob("AT-*.json"))) == 150
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["task_count"] == 150
    assert manifest["full_file_contexts"] + manifest["windowed_contexts"] == 150
    for relative, expected in manifest["files"].items():
        actual = hashlib.sha256((BASE_DIR / relative).read_bytes()).hexdigest()
        assert actual == expected

    print("Model annotation bundle validation: PASS")
    print(f"Tasks: {len(records)}")
    print(f"Full-file/windowed: {manifest['full_file_contexts']}/{manifest['windowed_contexts']}")
    print("Blinding: PASS (no confidence, split, detector, or weights)")
    print("Per-task equivalence: PASS")
    print("Prompt/schema/input hashes: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

