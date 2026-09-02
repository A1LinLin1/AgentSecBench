"""Create a compact, provenance-preserving Security-ADG mutation ablation table."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "mutations" / "agentsecbench_mutate_v2_ablation.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, action="append", required=True, help="One evaluator JSON per frozen analysis mode.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    rows = []
    for path in args.input:
        payload = json.loads(path.read_text(encoding="utf-8"))
        overall = payload["overall"]
        rows.append({
            "analysis_mode": path.stem.removeprefix("agentsecbench_mutate_v2_").removesuffix("_results"),
            "result_path": path.resolve().relative_to(BASE_DIR).as_posix(),
            "mutation_count": payload["mutation_count"],
            "dependency_f1": overall["dependency"]["f1"],
            "source_type_precision": overall["source_type_relation"]["precision"],
            "source_type_recall": overall["source_type_relation"]["recall"],
            "source_type_f1": overall["source_type_relation"]["f1"],
            "guard_kind_f1": overall["guard_kind_relation"]["f1"],
            "exact_oracle_matches": overall["exact_oracle_matches"],
            "mismatch_count": len(payload["mismatches"]),
        })
    report = {
        "suite": "agentsecbench_mutate_v2",
        "evaluation_protocol": "All listed engines existed before this independently selected mutation suite was built; no v2 oracle was supplied to any engine.",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
