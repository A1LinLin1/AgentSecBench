"""Analyze inter-model agreement and build a post-annotation review queue."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "annotations" / "model_annotation"
TASKS_PATH = BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl"
PROVIDERS = ("openai", "anthropic", "gemini", "qwen", "deepseek")
FIELDS = (
    "behavior_confirmed",
    "agent_relevant",
    "source_type",
    "source_external",
    "dependency_confirmed",
    "trust_boundary_crossed",
    "effect_type",
    "guard_present",
    "guard_effective",
    "weakness_present",
    "vulnerability_status",
    "label_confidence",
)
CORE_FIELDS = {
    "behavior_confirmed": 1.5,
    "agent_relevant": 1.5,
    "dependency_confirmed": 2.0,
    "trust_boundary_crossed": 2.0,
    "weakness_present": 2.5,
    "vulnerability_status": 3.0,
}


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def percentile(values: list[float], probability: float) -> float | None:
    values = sorted(value for value in values if not math.isnan(value))
    if not values:
        return None
    position = (len(values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return values[lower]
    return values[lower] + (values[upper] - values[lower]) * (position - lower)


def fleiss(rows: list[list[str]]) -> tuple[float, float, float]:
    """Return Fleiss' kappa, observed pair agreement, and expected agreement."""
    if not rows:
        return math.nan, math.nan, math.nan
    raters = len(rows[0])
    if raters < 2 or any(len(row) != raters for row in rows):
        raise ValueError("Fleiss' kappa requires a fixed number of at least two raters")
    totals = Counter(label for row in rows for label in row)
    observed = sum(
        sum(count * (count - 1) for count in Counter(row).values())
        / (raters * (raters - 1))
        for row in rows
    ) / len(rows)
    denominator = len(rows) * raters
    expected = sum((count / denominator) ** 2 for count in totals.values())
    kappa = math.nan if math.isclose(expected, 1.0) else (observed - expected) / (1 - expected)
    return kappa, observed, expected


def field_metrics(rows: list[list[str]], bootstrap: int, rng: random.Random) -> dict:
    kappa, observed, expected = fleiss(rows)
    raters = len(rows[0])
    maxima = [max(Counter(row).values()) for row in rows]
    boot = []
    for _ in range(bootstrap):
        sample = [rows[rng.randrange(len(rows))] for _ in rows]
        boot.append(fleiss(sample)[0])
    labels = Counter(label for row in rows for label in row)
    return {
        "fleiss_kappa": None if math.isnan(kappa) else round(kappa, 6),
        "fleiss_kappa_ci95_low": (
            None if (value := percentile(boot, 0.025)) is None else round(value, 6)
        ),
        "fleiss_kappa_ci95_high": (
            None if (value := percentile(boot, 0.975)) is None else round(value, 6)
        ),
        "pairwise_agreement": round(observed, 6),
        "chance_expected_agreement": round(expected, 6),
        "unanimous_rate": round(sum(value == raters for value in maxima) / len(rows), 6),
        "strict_majority_rate": round(sum(value >= 3 for value in maxima) / len(rows), 6),
        "mean_majority_vote_fraction": round(sum(maxima) / (len(rows) * raters), 6),
        "label_counts": dict(sorted(labels.items())),
    }


def vote_summary(labels: list[str]) -> dict:
    counts = Counter(labels)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    tied = len(ordered) > 1 and ordered[0][1] == ordered[1][1]
    return {
        "plurality_label": None if tied else ordered[0][0],
        "top_vote_count": ordered[0][1],
        "counts": dict(sorted(counts.items())),
        "tie": tied,
    }


def atomic_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", default="panel_v3_hybrid")
    parser.add_argument("--bootstrap", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20260806)
    args = parser.parse_args()
    if args.bootstrap < 0:
        parser.error("--bootstrap must be non-negative")

    run_dir = MODEL_DIR / "runs" / args.run_id
    output_dir = run_dir / "analysis"
    output_dir.mkdir(parents=True, exist_ok=True)
    tasks = {row["task_id"]: row for row in read_jsonl(TASKS_PATH)}
    annotations: dict[str, dict[str, dict]] = {}
    for provider in PROVIDERS:
        path = run_dir / "normalized" / f"{provider}.jsonl"
        rows = read_jsonl(path)
        if len(rows) != len(tasks):
            raise RuntimeError(f"{provider}: expected {len(tasks)} rows, found {len(rows)}")
        for row in rows:
            annotations.setdefault(row["task_id"], {})[provider] = row["annotation"]
    missing = {
        task_id: sorted(set(PROVIDERS) - set(by_provider))
        for task_id, by_provider in annotations.items()
        if set(by_provider) != set(PROVIDERS)
    }
    if missing or set(annotations) != set(tasks):
        raise RuntimeError(f"incomplete panel: missing providers={missing}")

    rng = random.Random(args.seed)
    metrics = {}
    for field in FIELDS:
        rows = [
            [annotations[task_id][provider][field] for provider in PROVIDERS]
            for task_id in sorted(tasks)
        ]
        metrics[field] = field_metrics(rows, args.bootstrap, rng)

    report = {
        "run_id": args.run_id,
        "interpretation": (
            "Inter-model agreement only; these labels are pre-annotations, not ground truth "
            "and not a substitute for independent human annotation and adjudication."
        ),
        "tasks": len(tasks),
        "raters_per_task": len(PROVIDERS),
        "completed_annotations": len(tasks) * len(PROVIDERS),
        "providers": list(PROVIDERS),
        "bootstrap_replicates": args.bootstrap,
        "bootstrap_seed": args.seed,
        "fields": metrics,
    }
    atomic_json(output_dir / "agreement_summary.json", report)

    with (output_dir / "agreement_summary.csv").open("w", encoding="utf-8", newline="") as handle:
        columns = [
            "field", "fleiss_kappa", "fleiss_kappa_ci95_low", "fleiss_kappa_ci95_high",
            "pairwise_agreement", "chance_expected_agreement", "unanimous_rate",
            "strict_majority_rate", "mean_majority_vote_fraction", "label_counts_json",
        ]
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for field in FIELDS:
            row = {"field": field, **metrics[field]}
            row["label_counts_json"] = json.dumps(row.pop("label_counts"), sort_keys=True)
            writer.writerow(row)

    queue = []
    for task_id in sorted(tasks):
        task = tasks[task_id]
        field_votes = {}
        disagreement_score = 0.0
        disagreement_fields = []
        for field in FIELDS:
            labels = [annotations[task_id][provider][field] for provider in PROVIDERS]
            summary = vote_summary(labels)
            field_votes[field] = {
                **summary,
                "by_provider": dict(zip(PROVIDERS, labels)),
            }
            disagreement = 1 - summary["top_vote_count"] / len(PROVIDERS)
            if disagreement:
                disagreement_fields.append(field)
            disagreement_score += disagreement * CORE_FIELDS.get(field, 1.0)
        core_low_consensus = any(
            field_votes[field]["top_vote_count"] <= 3 for field in CORE_FIELDS
        )
        vulnerability_split = field_votes["vulnerability_status"]["top_vote_count"] < 5
        if core_low_consensus or vulnerability_split or disagreement_score >= 2.5:
            priority = "HIGH"
        elif disagreement_fields:
            priority = "MEDIUM"
        else:
            priority = "LOW"
        queue.append(
            {
                "task_id": task_id,
                "candidate_id": task["candidate_id"],
                "repo": task["repo"],
                "file": task["file"],
                "evidence_lines": task["evidence_lines"],
                "experiment_split": task["experiment_split"],
                "candidate_behavior": task["candidate_behavior"],
                "priority": priority,
                "disagreement_score": round(disagreement_score, 4),
                "disagreement_fields": disagreement_fields,
                "votes": field_votes,
                "model_rationales": {
                    provider: annotations[task_id][provider]["rationale"] for provider in PROVIDERS
                },
                "human_review_required": True,
            }
        )
    priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    queue.sort(key=lambda row: (priority_order[row["priority"]], -row["disagreement_score"], row["task_id"]))

    with (output_dir / "model_disagreement_queue.jsonl").open("w", encoding="utf-8") as handle:
        for row in queue:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    with (output_dir / "model_disagreement_queue.csv").open("w", encoding="utf-8", newline="") as handle:
        columns = [
            "review_rank", "task_id", "candidate_id", "repo", "file", "evidence_lines",
            "experiment_split", "candidate_behavior", "priority", "disagreement_score",
            "disagreement_fields", "behavior_vote", "weakness_vote", "vulnerability_vote",
            "human_review_required",
        ]
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for rank, row in enumerate(queue, start=1):
            writer.writerow(
                {
                    "review_rank": rank,
                    **{key: row[key] for key in columns if key in row},
                    "evidence_lines": json.dumps(row["evidence_lines"]),
                    "disagreement_fields": ";".join(row["disagreement_fields"]),
                    "behavior_vote": json.dumps(row["votes"]["behavior_confirmed"]["counts"], sort_keys=True),
                    "weakness_vote": json.dumps(row["votes"]["weakness_present"]["counts"], sort_keys=True),
                    "vulnerability_vote": json.dumps(row["votes"]["vulnerability_status"]["counts"], sort_keys=True),
                }
            )

    priority_counts = Counter(row["priority"] for row in queue)
    print(f"Analyzed {len(tasks)} tasks x {len(PROVIDERS)} models")
    print("Review priority: " + ", ".join(f"{key}={priority_counts[key]}" for key in ("HIGH", "MEDIUM", "LOW")))
    for field in FIELDS:
        value = metrics[field]
        print(
            f"{field}: kappa={value['fleiss_kappa']} "
            f"pairwise={value['pairwise_agreement']} unanimous={value['unanimous_rate']}"
        )
    print(f"Saved: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
