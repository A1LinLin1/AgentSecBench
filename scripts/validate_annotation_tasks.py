"""Validate annotation tasks against frozen findings and the pilot manifest."""

from __future__ import annotations

import csv
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
FINDINGS = BASE_DIR / "analysis" / "raw_findings.jsonl"
MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
TASKS = BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl"
ANNOTATORS = [
    BASE_DIR / "annotations" / "annotator" / "annotator_a.jsonl",
    BASE_DIR / "annotations" / "annotator" / "annotator_b.jsonl",
]


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def main() -> int:
    findings = read_jsonl(FINDINGS)
    tasks = read_jsonl(TASKS)
    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest = {row["repo"]: row for row in csv.DictReader(handle)}
    by_candidate = {row["annotation_id"]: row for row in findings}

    assert len(findings) == 531
    assert len(tasks) == 150
    assert len({task["task_id"] for task in tasks}) == 150
    assert len({task["candidate_id"] for task in tasks}) == 150
    assert Counter(task["candidate_confidence"] for task in tasks) == {
        "high": 100,
        "medium": 50,
    }

    populations: Counter[str] = Counter()
    samples: Counter[str] = Counter()
    for finding in findings:
        key = "|".join((finding["confidence"], finding["repo"], finding["category"]))
        populations[key] += 1
    for task in tasks:
        samples[task["sampling_stratum"]] += 1
    assert set(samples) == set(populations)

    for task in tasks:
        finding = by_candidate[task["candidate_id"]]
        row = manifest[task["repo"]]
        for task_key, finding_key in (
            ("sample_id", "sample_id"),
            ("repo", "repo"),
            ("git_commit", "git_commit"),
            ("candidate_behavior", "category"),
            ("candidate_confidence", "confidence"),
            ("file", "file"),
            ("symbol", "symbol"),
            ("evidence_lines", "evidence_lines"),
            ("evidence_line_sha256", "evidence_line_sha256"),
            ("detector", "detector"),
        ):
            assert task[task_key] == finding[finding_key]
        assert task["git_commit"] == row["git_commit"]
        assert task["experiment_split"] == row["experiment_split"]
        assert task["use_for_method_tuning"] == row["use_for_method_tuning"]

        population = populations[task["sampling_stratum"]]
        sample = samples[task["sampling_stratum"]]
        assert task["stratum_population"] == population
        assert task["stratum_sample_size"] == sample
        assert math.isclose(task["inclusion_probability"], sample / population)
        assert math.isclose(task["sample_weight"], population / sample)

    task_pairs = [(task["task_id"], task["candidate_id"]) for task in tasks]
    for expected_annotator, path in zip(("A", "B"), ANNOTATORS, strict=True):
        rows = read_jsonl(path)
        assert len(rows) == 150
        assert [(row["task_id"], row["candidate_id"]) for row in rows] == task_pairs
        assert all(row["annotator"] == expected_annotator for row in rows)
        assert all(row["behavior_confirmed"] is None for row in rows)

    print("Annotation task validation: PASS")
    print(f"Population candidates: {len(findings)}")
    print(f"Sampled tasks: {len(tasks)}")
    print(f"Covered strata: {len(samples)}/{len(populations)}")
    print(f"Confidence: {dict(Counter(t['candidate_confidence'] for t in tasks))}")
    print(f"Split: {dict(Counter(t['experiment_split'] for t in tasks))}")
    print(f"Repository: {dict(Counter(t['repo'] for t in tasks))}")
    print("Annotator files: 150 tasks each, aligned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

