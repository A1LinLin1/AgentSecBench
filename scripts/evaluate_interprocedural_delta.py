"""Compare paired intraprocedural and interprocedural product graph outputs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsecbench.evaluation import (  # noqa: E402
    EvaluationError,
    compare_interprocedural_graphs,
    markdown_report,
    read_jsonl,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-graphs", type=Path, required=True)
    parser.add_argument("--interprocedural-graphs", type=Path, required=True)
    parser.add_argument("--baseline-summary", type=Path)
    parser.add_argument("--interprocedural-summary", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        baseline_summary = json.loads(args.baseline_summary.read_text(encoding="utf-8")) if args.baseline_summary else None
        enhanced_summary = json.loads(args.interprocedural_summary.read_text(encoding="utf-8")) if args.interprocedural_summary else None
        report = compare_interprocedural_graphs(
            read_jsonl(args.baseline_graphs),
            read_jsonl(args.interprocedural_graphs),
            baseline_summary,
            enhanced_summary,
        )
    except (EvaluationError, OSError, json.JSONDecodeError) as error:
        print(f"interprocedural evaluation error: {error}", file=sys.stderr)
        return 2
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "interprocedural_delta.json"
    markdown_path = args.output_dir / "interprocedural_delta.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    markdown_path.write_text(markdown_report(report), encoding="utf-8", newline="\n")
    print(json.dumps({
        "status": "completed",
        "candidate_count": report["population_alignment"]["candidate_count"],
        "changed_candidate_count": report["changed_candidate_count"],
        "added_dependency_paths": report["path_refinement"]["added_interprocedural_paths"],
        "output": str(json_path),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
