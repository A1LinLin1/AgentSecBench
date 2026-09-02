"""Create a reproducible stratified annotation sample from pilot findings."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_FINDINGS = BASE_DIR / "analysis" / "raw_findings.jsonl"
DEFAULT_MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
DEFAULT_OUTPUT = BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl"
DEFAULT_CSV = BASE_DIR / "annotations" / "tasks" / "annotation_tasks.csv"
DEFAULT_A = BASE_DIR / "annotations" / "annotator" / "annotator_a.jsonl"
DEFAULT_B = BASE_DIR / "annotations" / "annotator" / "annotator_b.jsonl"

CONFIDENCE_QUOTAS = {"high": 100, "medium": 50}
DEFAULT_SEED = "agentsecbench-pilot-v1"

LABEL_FIELDS = {
    "behavior_confirmed": None,
    "agent_relevant": None,
    "source_type": None,
    "source_external": None,
    "dependency_confirmed": None,
    "trust_boundary_crossed": None,
    "effect_type": None,
    "effect_target": None,
    "guard_present": None,
    "guard_types": [],
    "guard_effective": None,
    "weakness_present": None,
    "vulnerability_status": "not_assessed",
    "label_confidence": None,
    "rationale": "",
}


def allocate_quotas(populations: dict[tuple[str, str, str], int]) -> dict[tuple[str, str, str], int]:
    allocations: dict[tuple[str, str, str], int] = {}
    by_confidence: dict[str, dict[tuple[str, str, str], int]] = defaultdict(dict)
    for stratum, count in populations.items():
        by_confidence[stratum[0]][stratum] = count

    for confidence, target in CONFIDENCE_QUOTAS.items():
        strata = by_confidence.get(confidence, {})
        if not strata:
            raise RuntimeError(f"no candidates for confidence stratum {confidence}")
        if target > sum(strata.values()):
            raise RuntimeError(f"quota {target} exceeds {confidence} population")
        if target < len(strata):
            raise RuntimeError(
                f"quota {target} cannot cover all {len(strata)} {confidence} strata"
            )

        for stratum in strata:
            allocations[stratum] = 1
        remaining = target - len(strata)
        capacities = {stratum: count - 1 for stratum, count in strata.items()}
        capacity_total = sum(capacities.values())
        ideals: dict[tuple[str, str, str], float] = {}
        for stratum, capacity in capacities.items():
            ideal = remaining * capacity / capacity_total if capacity_total else 0.0
            ideals[stratum] = ideal
            addition = min(capacity, int(ideal))
            allocations[stratum] += addition

        assigned = sum(allocations[stratum] for stratum in strata)
        leftovers = target - assigned
        ranked = sorted(
            strata,
            key=lambda stratum: (
                -(ideals[stratum] - int(ideals[stratum])),
                stratum,
            ),
        )
        while leftovers:
            progressed = False
            for stratum in ranked:
                if allocations[stratum] < strata[stratum]:
                    allocations[stratum] += 1
                    leftovers -= 1
                    progressed = True
                    if leftovers == 0:
                        break
            if not progressed:
                raise RuntimeError(f"could not allocate remaining {confidence} quota")
    return allocations


def deterministic_score(seed: str, candidate_id: str) -> str:
    return hashlib.sha256(f"{seed}\0{candidate_id}".encode("utf-8")).hexdigest()


def build_tasks(findings: list[dict], manifest: list[dict], seed: str) -> list[dict]:
    manifest_by_repo = {row["repo"]: row for row in manifest}
    grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for finding in findings:
        if finding["repo"] not in manifest_by_repo:
            raise RuntimeError(f"finding repository outside pilot: {finding['repo']}")
        stratum = (finding["confidence"], finding["repo"], finding["category"])
        grouped[stratum].append(finding)

    populations = {stratum: len(items) for stratum, items in grouped.items()}
    allocations = allocate_quotas(populations)
    sampled: list[tuple[tuple[str, str, str], dict]] = []
    for stratum, items in grouped.items():
        ordered = sorted(
            items,
            key=lambda item: (
                deterministic_score(seed, item["annotation_id"]),
                item["annotation_id"],
            ),
        )
        sampled.extend((stratum, item) for item in ordered[: allocations[stratum]])

    sampled.sort(
        key=lambda pair: (
            0 if manifest_by_repo[pair[1]["repo"]]["experiment_split"] == "development" else 1,
            pair[0],
            pair[1]["annotation_id"],
        )
    )

    tasks: list[dict] = []
    for index, (stratum, finding) in enumerate(sampled, start=1):
        confidence, repo, category = stratum
        population = populations[stratum]
        sample_size = allocations[stratum]
        manifest_row = manifest_by_repo[repo]
        tasks.append(
            {
                "task_id": f"AT-{index:04d}",
                "candidate_id": finding["annotation_id"],
                "sample_id": finding["sample_id"],
                "repo": repo,
                "git_commit": finding["git_commit"],
                "experiment_split": manifest_row["experiment_split"],
                "use_for_method_tuning": manifest_row["use_for_method_tuning"],
                "candidate_behavior": category,
                "candidate_confidence": confidence,
                "file": finding["file"],
                "symbol": finding["symbol"],
                "evidence_lines": finding["evidence_lines"],
                "evidence_line_sha256": finding["evidence_line_sha256"],
                "detector": finding["detector"],
                "sampling_stratum": "|".join(stratum),
                "stratum_population": population,
                "stratum_sample_size": sample_size,
                "inclusion_probability": sample_size / population,
                "sample_weight": population / sample_size,
                "sampling_seed": seed,
                "questions": [
                    "Is the detected operation real rather than a syntactic false positive?",
                    "Is the operation part of an agent capability or agent-controlled path?",
                    "Can an external or less-trusted source influence the operation?",
                    "Does the dependency cross a trust boundary?",
                    "Are technical guards present and effective?",
                    "Is this normal behavior, a weakness, or a vulnerability candidate?",
                ],
            }
        )
    return tasks


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    temporary.replace(path)


def write_csv(path: Path, tasks: list[dict]) -> None:
    fields = [
        "task_id",
        "candidate_id",
        "sample_id",
        "repo",
        "git_commit",
        "experiment_split",
        "use_for_method_tuning",
        "candidate_behavior",
        "candidate_confidence",
        "file",
        "symbol",
        "evidence_lines",
        "detector",
        "sampling_stratum",
        "stratum_population",
        "stratum_sample_size",
        "inclusion_probability",
        "sample_weight",
        "sampling_seed",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for task in tasks:
            writer.writerow({**task, "evidence_lines": ";".join(map(str, task["evidence_lines"]))})
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--annotator-a", type=Path, default=DEFAULT_A)
    parser.add_argument("--annotator-b", type=Path, default=DEFAULT_B)
    parser.add_argument("--seed", default=DEFAULT_SEED)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with args.findings.open("r", encoding="utf-8") as handle:
        findings = [json.loads(line) for line in handle if line.strip()]
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest = list(csv.DictReader(handle))

    tasks = build_tasks(findings, manifest, args.seed)
    if len(tasks) != sum(CONFIDENCE_QUOTAS.values()):
        raise RuntimeError(f"expected 150 tasks, produced {len(tasks)}")
    write_jsonl(args.output, tasks)
    write_csv(args.csv, tasks)

    for annotator, destination in (("A", args.annotator_a), ("B", args.annotator_b)):
        label_rows = [
            {
                "task_id": task["task_id"],
                "candidate_id": task["candidate_id"],
                "annotator": annotator,
                **LABEL_FIELDS,
            }
            for task in tasks
        ]
        write_jsonl(destination, label_rows)

    print(f"Annotation tasks: {len(tasks)}")
    print(f"Confidence quotas: {dict(Counter(t['candidate_confidence'] for t in tasks))}")
    print(f"Experiment splits: {dict(Counter(t['experiment_split'] for t in tasks))}")
    print(f"JSONL: {args.output}")
    print(f"CSV: {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
