"""Map security-tagged CodeQL SARIF results to candidate-level predictions."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path, PurePosixPath
from urllib.parse import unquote


BASE_DIR = Path(__file__).resolve().parent.parent


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def location_key(location: dict) -> tuple[str, int] | None:
    physical = location.get("physicalLocation", {})
    uri = physical.get("artifactLocation", {}).get("uri")
    line = physical.get("region", {}).get("startLine")
    if not uri or not line:
        return None
    normalized = PurePosixPath(unquote(uri).replace("\\", "/")).as_posix()
    return normalized.removeprefix("./"), int(line)


def result_locations(result: dict) -> set[tuple[str, int]]:
    locations = set()
    for wrapper in result.get("locations", []):
        key = location_key(wrapper)
        if key:
            locations.add(key)
    for code_flow in result.get("codeFlows", []):
        for thread_flow in code_flow.get("threadFlows", []):
            for wrapper in thread_flow.get("locations", []):
                key = location_key(wrapper.get("location", {}))
                if key:
                    locations.add(key)
    return locations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=BASE_DIR / "dataset" / "pilot_manifest.csv")
    parser.add_argument("--findings", type=Path, default=BASE_DIR / "analysis" / "raw_findings.jsonl")
    parser.add_argument("--tasks", type=Path, default=BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl")
    parser.add_argument("--input-dir", type=Path, default=BASE_DIR / "analysis" / "baselines" / "development" / "codeql" / "sarif")
    parser.add_argument("--output", type=Path, default=BASE_DIR / "analysis" / "baselines" / "development" / "codeql_predictions.jsonl")
    parser.add_argument("--split", choices=("development", "held_out_evaluation"), default="development")
    parser.add_argument("--method", default="codeql_security_and_quality_v2_buildmode_none")
    parser.add_argument("--run-id", default="codeql_security_and_quality_v2_buildmode_none")
    args = parser.parse_args()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest = [row for row in csv.DictReader(handle) if row["experiment_split"] == args.split]
    samples = {row["sample_id"] for row in manifest}
    candidates = [row for row in read_jsonl(args.findings) if row["sample_id"] in samples]
    task_ids = {row["candidate_id"] for row in read_jsonl(args.tasks) if row["experiment_split"] == args.split}
    matched: dict[str, list[dict]] = {candidate["annotation_id"]: [] for candidate in candidates}
    result_counts = Counter()
    for sarif_path in sorted(args.input_dir.glob("*.sarif")):
        sample_id = sarif_path.stem.split("_", 1)[0]
        if sample_id not in samples:
            continue
        payload = json.loads(sarif_path.read_text(encoding="utf-8"))
        for sarif_run in payload.get("runs", []):
            rules = {rule["id"]: rule for rule in sarif_run.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in sarif_run.get("results", []):
                rule = rules.get(result.get("ruleId"), {})
                properties = rule.get("properties", {})
                tags = properties.get("tags", [])
                if "security" not in tags:
                    result_counts["non_security_excluded"] += 1
                    continue
                result_counts["security"] += 1
                kind = properties.get("kind", "unknown")
                locations = result_locations(result)
                for candidate in candidates:
                    if candidate["sample_id"] != sample_id:
                        continue
                    candidate_path = candidate["file"].replace("\\", "/")
                    overlaps = sorted(
                        line for path, line in locations
                        if path == candidate_path and candidate["line_start"] <= line <= candidate["line_end"]
                    )
                    if overlaps:
                        matched[candidate["annotation_id"]].append(
                            {
                                "rule": result.get("ruleId"),
                                "kind": kind,
                                "lines": overlaps,
                                "has_code_flow": bool(result.get("codeFlows")),
                                "sarif": sarif_path.name,
                            }
                        )
    predictions = []
    for candidate in candidates:
        candidate_id = candidate["annotation_id"]
        if candidate_id not in task_ids:
            continue
        evidence = matched[candidate_id]
        dependency_evidence = [
            item for item in evidence if item["kind"] == "path-problem" and item["has_code_flow"]
        ]
        for field, prediction, field_evidence in (
            ("weakness_present", bool(evidence), evidence),
            ("dependency_confirmed", bool(dependency_evidence), dependency_evidence),
        ):
            predictions.append(
                {
                    "candidate_id": candidate_id,
                    "method": args.method,
                    "field": field,
                    "prediction": prediction,
                    "run_id": args.run_id,
                    "evidence": field_evidence,
                }
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in predictions:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    by_field = {
        field: {
            "predictions": len([row for row in predictions if row["field"] == field]),
            "positive": len([row for row in predictions if row["field"] == field and row["prediction"]]),
        }
        for field in ("weakness_present", "dependency_confirmed")
    }
    summary = {
        "sarif_results": dict(sorted(result_counts.items())),
        "candidate_matches": sum(bool(value) for value in matched.values()),
        "fields": by_field,
        "label_inputs_used": False,
    }
    args.output.with_suffix(".summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
