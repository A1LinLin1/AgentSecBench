#!/usr/bin/env python3
"""Build a guard-aware representation ablation table from a case matrix.

The output is paper-facing qualitative evidence, not a precision/recall/F1
report. It asks what each representation can express for the same confirmed
held-out reproduction cases:

- sink-only: operation/API presence;
- plain ADG: local program structure and effect;
- Security-ADG: source/dependency path, trust boundary, and guard posture.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = BASE_DIR / "analysis" / "reproduction" / "case_matrix" / "heldout_reproduction_case_matrix.json"
DEFAULT_OUTPUT_DIR = BASE_DIR / "analysis" / "reproduction" / "guard_ablation"


VIEWS = [
    {
        "view": "sink_only",
        "display_name": "Sink-only",
        "definition": "A security-sensitive API or operation is present.",
        "operation": True,
        "effect": False,
        "dependency": False,
        "trust_boundary": False,
        "guard": False,
    },
    {
        "view": "plain_adg",
        "display_name": "Simplified ADG",
        "definition": "The program contains a security-sensitive operation that may cause an external effect.",
        "operation": True,
        "effect": True,
        "dependency": False,
        "trust_boundary": False,
        "guard": False,
    },
    {
        "view": "security_adg",
        "display_name": "Security-ADG",
        "definition": "The graph preserves operation, effect, source/dependency, trust-boundary, and guard evidence.",
        "operation": True,
        "effect": True,
        "dependency": True,
        "trust_boundary": True,
        "guard": True,
    },
]


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(BASE_DIR).as_posix()
    except ValueError:
        return resolved.as_posix()


def read_matrix(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def has_dependency(row: dict[str, Any]) -> bool:
    return bool(str(row.get("dependency_path", "")).strip())


def has_trust_boundary(row: dict[str, Any]) -> bool:
    return bool(str(row.get("trust_boundary", "")).strip()) and row.get("trust_boundary") != "not classified"


def is_guarded(row: dict[str, Any]) -> bool:
    return row.get("guard_posture") in {"guarded", "guard_context_present"}


def row_support(row: dict[str, Any], view: dict[str, Any]) -> dict[str, Any]:
    operation = bool(view["operation"] and row.get("sink_family"))
    effect = bool(view["effect"] and row.get("sink_family"))
    dependency = bool(view["dependency"] and has_dependency(row))
    trust = bool(view["trust_boundary"] and has_trust_boundary(row))
    guard = bool(view["guard"] and is_guarded(row))
    can_distinguish_guarded = bool(view["guard"])
    if view["view"] == "sink_only":
        interpretation = "API/operation presence only; guard and dependency context are invisible."
    elif view["view"] == "plain_adg":
        interpretation = "Operation/effect structure is visible, but source dependency and guard posture are collapsed."
    else:
        interpretation = (
            "Security context is visible: dependency path and trust boundary are explicit"
            + (" and guard evidence is preserved." if guard else "; no guard evidence is confirmed.")
        )
    return {
        "case_id": row["id"],
        "repository": row["repository"],
        "behavior_family": row["behavior_family"],
        "guard_posture": row["guard_posture"],
        "view": view["view"],
        "display_name": view["display_name"],
        "sees_operation": operation,
        "sees_effect": effect,
        "sees_dependency_path": dependency,
        "sees_trust_boundary": trust,
        "sees_guard": guard,
        "can_distinguish_guarded_from_unguarded": can_distinguish_guarded,
        "expressive_context_fields": sum([operation, effect, dependency, trust, guard]),
        "interpretation": interpretation,
    }


def build_case_rows(matrix_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row_support(row, view) for row in matrix_rows for view in VIEWS]


def pct(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 4)


def build_view_rows(case_rows: list[dict[str, Any]], case_count: int, guarded_count: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for view in VIEWS:
        subset = [row for row in case_rows if row["view"] == view["view"]]
        operation = sum(row["sees_operation"] for row in subset)
        effect = sum(row["sees_effect"] for row in subset)
        dependency = sum(row["sees_dependency_path"] for row in subset)
        trust = sum(row["sees_trust_boundary"] for row in subset)
        guard = sum(row["sees_guard"] for row in subset)
        rows.append(
            {
                "view": view["view"],
                "display_name": view["display_name"],
                "definition": view["definition"],
                "cases": case_count,
                "operation_visible": operation,
                "effect_visible": effect,
                "dependency_path_visible": dependency,
                "trust_boundary_visible": trust,
                "guard_visible": guard,
                "guarded_cases": guarded_count,
                "guard_recall_within_confirmed_guarded_cases": pct(guard, guarded_count),
                "context_completeness": pct(operation + effect + dependency + trust + guard, case_count * 5),
                "primary_limitation": primary_limitation(view["view"]),
            }
        )
    return rows


def primary_limitation(view: str) -> str:
    if view == "sink_only":
        return "Cannot distinguish reachable behavior from API presence or guarded from unguarded cases."
    if view == "plain_adg":
        return "Does not preserve security-specific source, trust-boundary, or guard semantics."
    return "Still qualitative; requires independent held-out labels before reporting accuracy metrics."


def build_summary(matrix: dict[str, Any]) -> dict[str, Any]:
    matrix_rows = matrix.get("rows", [])
    case_rows = build_case_rows(matrix_rows)
    guarded_count = sum(is_guarded(row) for row in matrix_rows)
    view_rows = build_view_rows(case_rows, len(matrix_rows), guarded_count)
    return {
        "schema_version": "1.0",
        "purpose": "guard-aware representation ablation for held-out reproduction cases; not a final metric report",
        "source_matrix_claim_boundary": matrix.get("claim_boundary", ""),
        "case_count": len(matrix_rows),
        "guarded_cases": guarded_count,
        "repositories": matrix.get("repositories", {}),
        "ecosystems": matrix.get("ecosystems", {}),
        "behavior_families": matrix.get("behavior_families", {}),
        "guard_postures": matrix.get("guard_postures", {}),
        "human_labels_used": matrix.get("human_labels_used", False),
        "model_labels_used": matrix.get("model_labels_used", False),
        "view_rows": view_rows,
        "case_view_rows": case_rows,
        "headline": {
            "sink_only_guard_visible": next(row["guard_visible"] for row in view_rows if row["view"] == "sink_only"),
            "plain_adg_guard_visible": next(row["guard_visible"] for row in view_rows if row["view"] == "plain_adg"),
            "security_adg_guard_visible": next(row["guard_visible"] for row in view_rows if row["view"] == "security_adg"),
            "security_adg_context_completeness": next(row["context_completeness"] for row in view_rows if row["view"] == "security_adg"),
        },
    }


def write_json(report: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def write_view_csv(rows: list[dict[str, Any]], path: Path) -> None:
    fieldnames = [
        "view",
        "display_name",
        "cases",
        "operation_visible",
        "effect_visible",
        "dependency_path_visible",
        "trust_boundary_visible",
        "guard_visible",
        "guarded_cases",
        "guard_recall_within_confirmed_guarded_cases",
        "context_completeness",
        "primary_limitation",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def write_case_csv(rows: list[dict[str, Any]], path: Path) -> None:
    fieldnames = [
        "case_id",
        "repository",
        "behavior_family",
        "guard_posture",
        "view",
        "sees_operation",
        "sees_effect",
        "sees_dependency_path",
        "sees_trust_boundary",
        "sees_guard",
        "expressive_context_fields",
        "interpretation",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def md_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", "<br>")


def yesno(value: Any) -> str:
    return "yes" if value else "no"


def write_markdown(report: dict[str, Any], path: Path) -> None:
    lines = [
        "# Guard-aware Representation Ablation",
        "",
        "This table compares what each representation can express for the same confirmed held-out reproduction cases. It is not a final precision, recall, or F1 report.",
        "",
        "## Summary",
        "",
        f"- Cases: {report['case_count']}",
        f"- Guarded cases: {report['guarded_cases']}",
        f"- Human labels used: {str(report['human_labels_used']).lower()}",
        f"- Model labels used: {str(report['model_labels_used']).lower()}",
        "",
        "## View-level ablation",
        "",
        "| View | Operation | Effect | Dependency path | Trust boundary | Guard | Guarded-case guard coverage | Context completeness | Main limitation |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in report["view_rows"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    md_escape(row["display_name"]),
                    str(row["operation_visible"]),
                    str(row["effect_visible"]),
                    str(row["dependency_path_visible"]),
                    str(row["trust_boundary_visible"]),
                    str(row["guard_visible"]),
                    f"{row['guard_recall_within_confirmed_guarded_cases']:.2%}",
                    f"{row['context_completeness']:.2%}",
                    md_escape(row["primary_limitation"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Case-level guard visibility",
            "",
            "| Case | Behavior | Guard posture | Sink-only sees guard | Plain ADG sees guard | Security-ADG sees guard |",
            "| --- | --- | --- | ---: | ---: | ---: |",
        ]
    )
    by_case: dict[str, list[dict[str, Any]]] = {}
    for row in report["case_view_rows"]:
        by_case.setdefault(row["case_id"], []).append(row)
    for case_id in sorted(by_case):
        rows = {row["view"]: row for row in by_case[case_id]}
        base = rows["security_adg"]
        lines.append(
            "| "
            + " | ".join(
                [
                    md_escape(case_id),
                    md_escape(base["behavior_family"]),
                    md_escape(base["guard_posture"]),
                    yesno(rows["sink_only"]["sees_guard"]),
                    yesno(rows["plain_adg"]["sees_guard"]),
                    yesno(rows["security_adg"]["sees_guard"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Paper claim boundary",
            "",
            "- This ablation supports the RQ4 claim that Security-ADG preserves security context omitted by sink-only and simplified ADG views.",
            "- It should not be reported as method accuracy. Accuracy requires the independent held-out gold set and adjudication.",
            "- The guard coverage denominator here is the set of reproduction-confirmed cases whose local evidence explicitly records guard context.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    matrix = read_matrix(args.matrix)
    report = build_summary(matrix)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.output_dir / "guard_ablation_summary.json"
    view_csv_path = args.output_dir / "guard_ablation_view_table.csv"
    case_csv_path = args.output_dir / "guard_ablation_case_view_table.csv"
    md_path = args.output_dir / "guard_ablation_table.md"
    write_json(report, summary_path)
    write_view_csv(report["view_rows"], view_csv_path)
    write_case_csv(report["case_view_rows"], case_csv_path)
    write_markdown(report, md_path)
    print(
        json.dumps(
            {
                "status": "complete",
                "cases": report["case_count"],
                "guarded_cases": report["guarded_cases"],
                "view_rows": len(report["view_rows"]),
                "case_view_rows": len(report["case_view_rows"]),
                "headline": report["headline"],
                "outputs": {
                    "summary": display_path(summary_path),
                    "view_csv": display_path(view_csv_path),
                    "case_csv": display_path(case_csv_path),
                    "md": display_path(md_path),
                },
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
