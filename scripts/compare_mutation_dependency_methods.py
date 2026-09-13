"""Perform a paired, exact comparison of sink-only and Security-ADG labels.

This script is intentionally limited to a controlled mutation oracle.  Its
McNemar result measures the paired disagreement on those fixed cases; it is
not a real-world vulnerability prevalence or human-label significance claim.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def exact_mcnemar_pvalue(only_left_correct: int, only_right_correct: int) -> float:
    """Two-sided exact binomial McNemar p-value for discordant pairs."""
    discordant = only_left_correct + only_right_correct
    if not discordant:
        return 1.0
    tail = sum(math.comb(discordant, index) for index in range(min(only_left_correct, only_right_correct) + 1))
    return min(1.0, 2.0 * tail / (2**discordant))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input", type=Path,
        default=BASE_DIR / "analysis" / "mutations" / "agentsecbench_mutate_v4_v2_4_results.json",
    )
    parser.add_argument(
        "--output", type=Path,
        default=BASE_DIR / "analysis" / "mutations" / "agentsecbench_mutate_v4_dependency_comparison.json",
    )
    args = parser.parse_args()
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    rows = payload["rows"]
    candidate_only = [bool(row["static_detected"]) for row in rows]
    security_adg = [bool(row["observed"]["dependency"]) for row in rows]
    expected = [bool(row["oracle"]["dependency"]) for row in rows]
    both_correct = sum(left == truth and right == truth for left, right, truth in zip(candidate_only, security_adg, expected))
    sink_only_correct = sum(left == truth and right != truth for left, right, truth in zip(candidate_only, security_adg, expected))
    security_adg_correct = sum(left != truth and right == truth for left, right, truth in zip(candidate_only, security_adg, expected))
    both_wrong = sum(left != truth and right != truth for left, right, truth in zip(candidate_only, security_adg, expected))
    result = {
        "scope": "controlled mutation oracle; paired dependency classification",
        "suite": payload["suite"],
        "cases": len(rows),
        "methods": {
            "sink_only": "a scanner-detected security-sensitive operation is treated as dependency-positive",
            "security_adg": "a candidate is dependency-positive only when local Security-ADG evidence contains a dependency path",
        },
        "paired_correctness": {
            "both_correct": both_correct,
            "sink_only_correct_security_adg_wrong": sink_only_correct,
            "security_adg_correct_sink_only_wrong": security_adg_correct,
            "both_wrong": both_wrong,
        },
        "mcnemar_exact_two_sided_p": exact_mcnemar_pvalue(sink_only_correct, security_adg_correct),
        "interpretation": "A paired test on fixed synthetic mutations; it does not establish real-world vulnerability prevalence or replace human evaluation.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
