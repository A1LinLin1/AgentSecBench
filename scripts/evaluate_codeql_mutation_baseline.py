"""Measure official CodeQL security-suite coverage on AgentSecBench-Mutate.

This is deliberately a *capability* comparison, not a claim that CodeQL and
Security-ADG solve identical tasks.  A standard CodeQL vulnerability suite is
credited only when a security-tagged SARIF result overlaps a seeded mutation
file; path evidence is reported separately.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from urllib.parse import unquote


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CATALOG = BASE_DIR / "benchmarks" / "derived" / "agentsecbench_mutate_v2_complete_20260901" / "mutation_catalog.json"
DEFAULT_SARIF = BASE_DIR / "analysis" / "baselines" / "mutation_v2" / "codeql_security_and_quality_v2" / "sarif"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "mutations" / "agentsecbench_mutate_v2_codeql_security_and_quality_v2_results.json"


def locations(result: dict) -> set[tuple[str, int]]:
    found: set[tuple[str, int]] = set()
    wrappers = list(result.get("locations", []))
    for flow in result.get("codeFlows", []):
        for thread in flow.get("threadFlows", []):
            wrappers.extend(item.get("location", {}) for item in thread.get("locations", []))
    for wrapper in wrappers:
        physical = wrapper.get("physicalLocation", {})
        uri = physical.get("artifactLocation", {}).get("uri")
        line = physical.get("region", {}).get("startLine")
        if uri and line:
            path = PurePosixPath(unquote(uri).replace("\\", "/")).as_posix().removeprefix("./")
            found.add((path, int(line)))
    return found


def load_security_results(sarif_dir: Path) -> tuple[dict[str, list[dict]], int, Counter]:
    by_sample: dict[str, list[dict]] = defaultdict(list)
    total = 0
    rules = Counter()
    for path in sorted(sarif_dir.glob("*.sarif")):
        sample_id = path.stem.split("_", 1)[0]
        payload = json.loads(path.read_text(encoding="utf-8"))
        for run in payload.get("runs", []):
            metadata = {
                rule["id"]: rule.get("properties", {})
                for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            }
            for result in run.get("results", []):
                properties = metadata.get(result.get("ruleId"), {})
                if "security" not in properties.get("tags", []):
                    continue
                total += 1
                rules[result.get("ruleId", "unknown")] += 1
                by_sample[sample_id].append({
                    "rule": result.get("ruleId"),
                    "kind": properties.get("kind", "unknown"),
                    "has_code_flow": bool(result.get("codeFlows")),
                    "locations": locations(result),
                })
    return by_sample, total, rules


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument("--sarif-dir", type=Path, default=DEFAULT_SARIF)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    by_sample, total_security, rules = load_security_results(args.sarif_dir)
    rows = []
    for mutation in catalog["mutations"]:
        evidence = [
            item for item in by_sample[mutation["source_sample_id"]]
            if any(path == mutation["file"] for path, _ in item["locations"])
        ]
        path_evidence = [item for item in evidence if item["kind"] == "path-problem" and item["has_code_flow"]]
        rows.append({
            "mutation_id": mutation["mutation_id"],
            "file": mutation["file"],
            "dependency_oracle": mutation["oracle"]["dependency"],
            "security_alert_at_mutation": bool(evidence),
            "path_evidence_at_mutation": bool(path_evidence),
            "evidence": [{key: item[key] for key in ("rule", "kind", "has_code_flow")} for item in evidence],
        })
    positive = [row for row in rows if row["dependency_oracle"]]
    negative = [row for row in rows if not row["dependency_oracle"]]
    report = {
        "suite": catalog["metadata"]["suite"],
        "baseline": "CodeQL 2.26.2 python-security-and-quality suite",
        "comparison_scope": "security-alert and path-evidence coverage, not source-type/guard classification",
        "oracle_used_only_after_baseline_execution": True,
        "mutation_count": len(rows),
        "dependency_positive_mutations": len(positive),
        "dependency_negative_mutations": len(negative),
        "total_security_sarif_results": total_security,
        "security_alert_coverage_on_dependency_positive": sum(row["security_alert_at_mutation"] for row in positive) / len(positive),
        "path_evidence_coverage_on_dependency_positive": sum(row["path_evidence_at_mutation"] for row in positive) / len(positive),
        "security_alerts_on_dependency_negative": sum(row["security_alert_at_mutation"] for row in negative),
        "path_evidence_on_dependency_negative": sum(row["path_evidence_at_mutation"] for row in negative),
        "matched_mutations": [row["mutation_id"] for row in rows if row["security_alert_at_mutation"]],
        "security_rule_counts": dict(sorted(rules.items())),
        "rows": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in (
        "suite", "mutation_count", "total_security_sarif_results",
        "security_alert_coverage_on_dependency_positive", "path_evidence_coverage_on_dependency_positive",
        "security_alerts_on_dependency_negative", "matched_mutations",
    )}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
