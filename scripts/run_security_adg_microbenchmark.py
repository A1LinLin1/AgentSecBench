"""Evaluate Security-ADG's local analysis contract on versioned fixtures.

This is an engine-mechanism benchmark with deterministic source/guard oracles.
It does not measure real-world vulnerability discovery or replace human labels.
"""

from __future__ import annotations

import argparse
import json
import runpy
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "scripts"))
from security_adg_dataflow import analyze  # noqa: E402


DEFAULT_CASES = BASE_DIR / "benchmarks" / "security_adg_micro" / "v1" / "cases.py"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "microbenchmark" / "security_adg_v1_results.json"


def metrics(tp: int, fp: int, fn: int, tn: int | None = None) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    result = {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}
    if tn is not None:
        result["tn"] = tn
        result["accuracy"] = (tp + tn) / (tp + fp + fn + tn) if tp + fp + fn + tn else None
    return result


def binary_counts(expected: list[bool], predicted: list[bool]) -> dict:
    tp = sum(a and b for a, b in zip(expected, predicted))
    fp = sum(not a and b for a, b in zip(expected, predicted))
    fn = sum(a and not b for a, b in zip(expected, predicted))
    tn = sum(not a and not b for a, b in zip(expected, predicted))
    return metrics(tp, fp, fn, tn)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--analysis-mode", choices=("v2_1", "v2_2", "v2_3", "v2_4"), default="v2_1")
    parser.add_argument("--fail-on-mismatch", action="store_true")
    args = parser.parse_args()
    cases = runpy.run_path(str(args.cases))["CASES"]

    scored = [case for case in cases if "known_limitation" not in case]
    source_expected: set[tuple[str, str]] = set()
    source_predicted: set[tuple[str, str]] = set()
    type_expected: set[tuple[str, str]] = set()
    type_predicted: set[tuple[str, str]] = set()
    guard_expected: set[tuple[str, str]] = set()
    guard_predicted: set[tuple[str, str]] = set()
    dependency_expected: list[bool] = []
    dependency_predicted: list[bool] = []
    source_presence_expected: list[bool] = []
    source_presence_predicted: list[bool] = []
    guard_presence_expected: list[bool] = []
    guard_presence_predicted: list[bool] = []
    details = []

    for case in cases:
        extension = ".py" if case["language"] == "python" else ".ts"
        result = analyze(
            case["source"],
            f"fixture{extension}",
            case["evidence_lines"],
            symbol=case.get("symbol"),
            prefer_parameter_sources=args.analysis_mode in {"v2_2", "v2_3", "v2_4"},
            respect_parameter_overwrites=args.analysis_mode in {"v2_3", "v2_4"},
            include_intrinsic_source_operation=args.analysis_mode != "v2_4",
        )
        predicted_symbols = sorted({item["symbol"] for item in result.sources})
        predicted_types = sorted({item["source_type"] for item in result.sources})
        predicted_guards = sorted({item["kind"] for item in result.guards})
        expected = case["expected"]
        expected_symbols = sorted(expected["source_symbols"])
        expected_types = sorted(expected["source_types"])
        expected_guards = sorted(expected["guard_kinds"])
        record = {
            "id": case["id"],
            "language": case["language"],
            "scored": "known_limitation" not in case,
            "known_limitation": case.get("known_limitation"),
            "expected": expected,
            "observed": {
                "operation_line": result.operation_line,
                "source_symbols": predicted_symbols,
                "source_types": predicted_types,
                "has_dependency_path": bool(result.dependency_paths),
                "guard_kinds": predicted_guards,
                "limitations": result.limitations,
            },
            "exact_match": {
                "source_symbols": expected_symbols == predicted_symbols,
                "source_types": expected_types == predicted_types,
                "dependency": expected["dependency"] == bool(result.dependency_paths),
                "guard_kinds": expected_guards == predicted_guards,
            },
        }
        details.append(record)
        if "known_limitation" in case:
            continue
        case_id = case["id"]
        source_expected.update((case_id, value) for value in expected_symbols)
        source_predicted.update((case_id, value) for value in predicted_symbols)
        type_expected.update((case_id, value) for value in expected_types)
        type_predicted.update((case_id, value) for value in predicted_types)
        guard_expected.update((case_id, value) for value in expected_guards)
        guard_predicted.update((case_id, value) for value in predicted_guards)
        dependency_expected.append(expected["dependency"])
        dependency_predicted.append(bool(result.dependency_paths))
        source_presence_expected.append(bool(expected_symbols))
        source_presence_predicted.append(bool(predicted_symbols))
        guard_presence_expected.append(bool(expected_guards))
        guard_presence_predicted.append(bool(predicted_guards))

    def set_metrics(expected: set[tuple[str, str]], predicted: set[tuple[str, str]]) -> dict:
        return metrics(len(expected & predicted), len(predicted - expected), len(expected - predicted))

    mismatch_count = sum(not all(record["exact_match"].values()) for record in details if record["scored"])
    report = {
        "benchmark": "security_adg_micro_v1",
        "analysis_mode": args.analysis_mode,
        "purpose": "Deterministic local-analysis mechanism validation; not real-world vulnerability evaluation.",
        "case_counts": {"total": len(cases), "scored": len(scored), "known_limitations": len(cases) - len(scored)},
        "metrics": {
            "source_symbol_relation": set_metrics(source_expected, source_predicted),
            "source_type_relation": set_metrics(type_expected, type_predicted),
            "guard_kind_relation": set_metrics(guard_expected, guard_predicted),
            "dependency_presence": binary_counts(dependency_expected, dependency_predicted),
            "source_presence": binary_counts(source_presence_expected, source_presence_predicted),
            "guard_presence": binary_counts(guard_presence_expected, guard_presence_predicted),
            "exact_case_matches": {"matched": len(scored) - mismatch_count, "mismatched": mismatch_count, "total": len(scored)},
        },
        "cases": details,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"case_counts": report["case_counts"], "metrics": report["metrics"]}, ensure_ascii=False, indent=2))
    if args.fail_on_mismatch and mismatch_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
