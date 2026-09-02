"""Summarize unlabeled full-corpus Security-ADG graphs and make a review queue.

The queue is a deterministic *review priority*, not a vulnerability score or
ground truth.  It deliberately uses only graph structure and static metadata.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = BASE_DIR / "dataset" / "corpus_manifest.csv"
DEFAULT_GRAPHS = BASE_DIR / "graphs" / "security_adg" / "all_corpus_v2_4.jsonl"
DEFAULT_SUMMARY = BASE_DIR / "analysis" / "all_corpus_security_adg_v2_4_summary.json"
DEFAULT_QUEUE = BASE_DIR / "analysis" / "review_queues" / "all_corpus_security_adg_v2_4_priority.jsonl"

IMPACT_WEIGHT = {
    "command_execution": 5,
    "dynamic_code_execution": 5,
    "permission_or_auth_change": 5,
    "credential_access": 4,
    "filesystem_delete": 4,
    "external_tool_invocation": 4,
    "network_access": 3,
    "message_or_email_send": 3,
    "database_access": 3,
    "filesystem_write": 3,
    "browser_control": 2,
    "filesystem_read": 2,
}
SOURCE_WEIGHT = {"agent_tool_parameter": 3, "source_api": 2, "function_parameter": 2, "intrinsic_source_operation": 1}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def category(graph: dict) -> str:
    return next(node["category"] for node in graph["nodes"] if node["type"] == "security_sensitive_operation")


def make_queue_row(graph: dict, metadata: dict) -> dict:
    sources = [node for node in graph["nodes"] if node["type"] == "input_source"]
    guards = [node for node in graph["nodes"] if node["type"] == "guard_candidate"]
    behavior = category(graph)
    source_types = sorted({node["source_type"] for node in sources})
    priority = IMPACT_WEIGHT.get(behavior, 1) + max((SOURCE_WEIGHT.get(item, 1) for item in source_types), default=0)
    if guards:
        priority -= 1
    operation = next(node for node in graph["nodes"] if node["type"] == "security_sensitive_operation")
    return {
        "candidate_id": graph["candidate_id"],
        "repo": graph["provenance"]["repo"],
        "sample_id": graph["provenance"]["sample_id"],
        "ecosystem": metadata.get("ecosystem", "unknown"),
        "language": metadata.get("dominant_language", "unknown"),
        "file": graph["provenance"]["file"],
        "behavior_category": behavior,
        "operation": operation["name"],
        "evidence_lines": operation["evidence_lines"],
        "source_types": source_types,
        "source_candidates": len(sources),
        "guard_kinds": sorted({node["kind"] for node in guards}),
        "dependency_paths": graph["analysis"]["dependency_paths"],
        "static_review_priority": priority,
        "ranking_note": "deterministic static review priority; not a vulnerability score",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--graphs", type=Path, default=DEFAULT_GRAPHS)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--max-queue", type=int, default=500)
    args = parser.parse_args()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        metadata = {row["repo"]: row for row in csv.DictReader(handle)}
    graphs = read_jsonl(args.graphs)
    by_category, by_ecosystem, by_language = Counter(), Counter(), Counter()
    structured = []
    for graph in graphs:
        behavior = category(graph)
        details = metadata[graph["provenance"]["repo"]]
        has_source = graph["views"]["security_adg"]["source_candidates"] > 0
        has_guard = graph["views"]["security_adg"]["guard_candidates"] > 0
        by_category[(behavior, has_source, has_guard)] += 1
        by_ecosystem[(details["ecosystem"], has_source)] += 1
        by_language[(details["dominant_language"], has_source)] += 1
        if has_source:
            structured.append(make_queue_row(graph, details))
    structured.sort(key=lambda row: (-row["static_review_priority"], row["behavior_category"], row["repo"], row["candidate_id"]))
    queue = structured[: args.max_queue]
    report = {
        "scope": "unlabeled all-corpus descriptive analysis",
        "graphs": len(graphs),
        "repositories_with_candidates": len({graph["provenance"]["repo"] for graph in graphs}),
        "graphs_with_def_use_source": len(structured),
        "graphs_with_guard_candidate": sum(graph["views"]["security_adg"]["guard_candidates"] > 0 for graph in graphs),
        "by_behavior": [
            {"category": key[0], "has_def_use_source": key[1], "has_guard_candidate": key[2], "count": value}
            for key, value in sorted(by_category.items())
        ],
        "by_ecosystem": [
            {"ecosystem": key[0], "has_def_use_source": key[1], "count": value}
            for key, value in sorted(by_ecosystem.items())
        ],
        "by_language": [
            {"language": key[0], "has_def_use_source": key[1], "count": value}
            for key, value in sorted(by_language.items())
        ],
        "review_queue": {
            "count": len(queue),
            "selection": "top deterministic static priorities among graphs with a local def-use source",
            "not_ground_truth": True,
        },
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.queue.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args.queue.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in queue), encoding="utf-8")
    print(json.dumps({
        "graphs": report["graphs"], "repositories_with_candidates": report["repositories_with_candidates"],
        "graphs_with_def_use_source": report["graphs_with_def_use_source"], "review_queue_count": len(queue),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
