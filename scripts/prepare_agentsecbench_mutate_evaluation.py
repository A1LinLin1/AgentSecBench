"""Align AgentSecBench-Mutate oracle entries with static-scanner findings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
ROOT = BASE_DIR / "benchmarks" / "derived" / "agentsecbench_mutate_v1"
DEFAULT_CATALOG = ROOT / "mutation_catalog.json"
DEFAULT_FINDINGS = BASE_DIR / "analysis" / "mutations" / "agentsecbench_mutate_v1_findings.jsonl"
DEFAULT_SELECTED = BASE_DIR / "analysis" / "mutations" / "agentsecbench_mutate_v1_oracle_findings.jsonl"
DEFAULT_ALIGNMENT = BASE_DIR / "analysis" / "mutations" / "agentsecbench_mutate_v1_static_alignment.json"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS)
    parser.add_argument("--selected-output", type=Path, default=DEFAULT_SELECTED)
    parser.add_argument("--alignment-output", type=Path, default=DEFAULT_ALIGNMENT)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    findings = read_jsonl(args.findings)
    selected, rows = [], []
    for mutation in catalog["mutations"]:
        matches = [
            finding for finding in findings
            if finding["repo"] == mutation["source_repo"]
            and finding["file"] == mutation["file"]
            and finding["symbol"] == mutation["symbol"]
            and finding["category"] == mutation["category"]
        ]
        rows.append({
            "mutation_id": mutation["mutation_id"],
            "language": mutation["language"],
            "file": mutation["file"],
            "symbol": mutation["symbol"],
            "category": mutation["category"],
            "oracle": mutation["oracle"],
            "static_detected": bool(matches),
            "candidate_ids": [item["annotation_id"] for item in matches],
        })
        if len(matches) > 1:
            raise RuntimeError(f"ambiguous scanner matches for {mutation['mutation_id']}: {len(matches)}")
        selected.extend(matches)
    if len({item["annotation_id"] for item in selected}) != len(selected):
        raise RuntimeError("one scanner finding was mapped to multiple mutations")
    args.selected_output.parent.mkdir(parents=True, exist_ok=True)
    args.selected_output.write_text("".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in selected), encoding="utf-8")
    report = {
        "suite": catalog["metadata"]["suite"],
        "mutation_count": len(rows),
        "static_detected": sum(row["static_detected"] for row in rows),
        "static_missed": [row["mutation_id"] for row in rows if not row["static_detected"]],
        "rows": rows,
    }
    args.alignment_output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("suite", "mutation_count", "static_detected", "static_missed")}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
