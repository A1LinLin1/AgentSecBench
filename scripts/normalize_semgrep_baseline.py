"""Map Semgrep sink findings to AgentSecBench candidate-level predictions."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=BASE_DIR / "dataset" / "pilot_manifest.csv")
    parser.add_argument("--findings", type=Path, default=BASE_DIR / "analysis" / "raw_findings.jsonl")
    parser.add_argument("--tasks", type=Path, default=BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl")
    parser.add_argument("--input-dir", type=Path, default=BASE_DIR / "analysis" / "baselines" / "development" / "semgrep")
    parser.add_argument("--output", type=Path, default=BASE_DIR / "analysis" / "baselines" / "development" / "semgrep_predictions.jsonl")
    parser.add_argument("--split", choices=("development", "held_out_evaluation"), default="development")
    parser.add_argument("--run-id", default="semgrep_predefined_sinks_v1")
    args = parser.parse_args()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest = list(csv.DictReader(handle))
    by_sample = {row["sample_id"]: row for row in manifest if row["experiment_split"] == args.split}
    candidates = [row for row in read_jsonl(args.findings) if row["sample_id"] in by_sample]
    task_ids = {row["candidate_id"] for row in read_jsonl(args.tasks) if row["experiment_split"] == args.split}
    matched: dict[str, list[dict]] = {candidate["annotation_id"]: [] for candidate in candidates}
    unmatched_findings = []
    for sample_id, manifest_row in by_sample.items():
        path = args.input_dir / f"{sample_id}.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        repo_root = (BASE_DIR / manifest_row["repository_path"]).resolve()
        for finding in payload.get("results", []):
            raw_path = Path(finding["path"])
            container_path = raw_path.as_posix()
            if container_path == "/src":
                relative = "."
            elif container_path.startswith("/src/"):
                # Docker baseline mounts each frozen repository at /src.
                relative = container_path.removeprefix("/src/")
            else:
                try:
                    relative = raw_path.resolve().relative_to(repo_root).as_posix()
                except ValueError:
                    relative = container_path
            category = finding.get("extra", {}).get("metadata", {}).get("category")
            start = int(finding["start"]["line"])
            end = int(finding["end"]["line"])
            matches = [
                candidate for candidate in candidates
                if candidate["sample_id"] == sample_id
                and candidate["file"].replace("\\", "/") == relative
                and candidate["category"] == category
                and not (end < candidate["line_start"] or start > candidate["line_end"])
            ]
            if not matches:
                unmatched_findings.append({"sample_id": sample_id, "file": relative, "line": start, "category": category, "rule": finding["check_id"]})
            for candidate in matches:
                matched[candidate["annotation_id"]].append(
                    {"rule": finding["check_id"], "line_start": start, "line_end": end}
                )
    predictions = []
    for candidate in candidates:
        candidate_id = candidate["annotation_id"]
        if candidate_id not in task_ids:
            continue
        evidence = matched[candidate_id]
        predictions.append(
            {
                "candidate_id": candidate_id,
                "method": "semgrep_predefined_sinks_v1",
                "field": "behavior_confirmed",
                "prediction": bool(evidence),
                "run_id": f"{args.run_id}_{args.split}",
                "evidence": evidence,
            }
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in predictions:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    summary = {
        "predictions": len(predictions),
        "positive": sum(row["prediction"] for row in predictions),
        "negative": sum(not row["prediction"] for row in predictions),
        "candidate_matches": sum(bool(value) for value in matched.values()),
        "unmatched_semgrep_findings": len(unmatched_findings),
        "unmatched_by_category": dict(sorted(Counter(item["category"] for item in unmatched_findings).items())),
        "label_inputs_used": False,
    }
    args.output.with_suffix(".summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
