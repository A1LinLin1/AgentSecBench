"""Run the reproducible AgentSecBench static-analysis and evidence-view pipeline."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def run(command: list[str]) -> None:
    print("+", " ".join(command))
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=BASE_DIR / "dataset" / "corpus_manifest.csv")
    parser.add_argument("--scope", choices=("all_corpus", "development", "held_out_evaluation", "mutation_evaluation"), default="all_corpus")
    parser.add_argument("--analysis-mode", choices=("v2_1", "v2_2", "v2_3", "v2_4"), default="v2_4")
    parser.add_argument("--output-root", type=Path, default=BASE_DIR / "artifacts" / "security_adg_pipeline")
    parser.add_argument("--skip-sample-id", action="append", default=[])
    parser.add_argument("--max-review-queue", type=int, default=500)
    parser.add_argument("--showcase-count", type=int, default=12)
    parser.add_argument("--showcase-candidate-id", action="append", default=[])
    args = parser.parse_args()

    root = args.output_root
    findings = root / "findings.jsonl"
    scan_summary = root / "static_scan_summary.csv"
    graphs = root / "security_adg.jsonl"
    graph_summary = root / "security_adg_summary.json"
    validation = root / "security_adg_validation.json"
    showcase = root / "showcase"
    root.mkdir(parents=True, exist_ok=True)

    scan_command = [sys.executable, str(BASE_DIR / "scripts" / "static_scan.py"), "--manifest", str(args.manifest), "--output", str(findings), "--summary", str(scan_summary)]
    for sample_id in args.skip_sample_id:
        scan_command.extend(["--skip-sample-id", sample_id])
    run(scan_command)
    graph_command = [sys.executable, str(BASE_DIR / "scripts" / "generate_security_adg_v2.py"), "--manifest", str(args.manifest), "--findings", str(findings), "--output", str(graphs), "--summary", str(graph_summary), "--split", args.scope, "--analysis-mode", args.analysis_mode, "--showcase-dir", str(showcase), "--showcase-max-graphs", str(args.showcase_count)]
    for candidate_id in args.showcase_candidate_id:
        graph_command.extend(["--showcase-candidate-id", candidate_id])
    run(graph_command)
    result = subprocess.run([sys.executable, str(BASE_DIR / "scripts" / "validate_security_adg.py"), "--input", str(graphs), "--expected-split", args.scope], check=True, capture_output=True, text=True)
    validation.write_text(result.stdout, encoding="utf-8")
    if args.scope == "all_corpus":
        run([sys.executable, str(BASE_DIR / "scripts" / "analyze_all_corpus_security_adg.py"), "--manifest", str(args.manifest), "--graphs", str(graphs), "--summary", str(root / "all_corpus_summary.json"), "--queue", str(root / "review_queue.jsonl"), "--max-queue", str(args.max_review_queue)])
    record = {
        "schema_version": "1.0", "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": args.scope, "analysis_mode": args.analysis_mode, "manifest": str(args.manifest),
        "skipped_sample_ids": args.skip_sample_id,
        "artifacts": {"findings": str(findings), "graphs": str(graphs), "validation": str(validation), "showcase": str(showcase / "index.html")},
    }
    (root / "pipeline_manifest.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
