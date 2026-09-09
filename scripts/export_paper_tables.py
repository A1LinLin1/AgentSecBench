#!/usr/bin/env python3
"""Export paper-ready CSV and LaTeX tables from a paper-results snapshot."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SNAPSHOT = BASE_DIR / "analysis" / "paper_results" / "paper_results_snapshot.json"
DEFAULT_OUTPUT_DIR = BASE_DIR / "analysis" / "paper_results" / "tables"


RQ3_COLUMNS = [
    ("id", "Case"),
    ("ecosystem", "Ecosystem"),
    ("behavior", "Behavior"),
    ("sink", "Sink"),
    ("guard_posture", "Guard"),
    ("evidence_mode", "Evidence"),
]


RQ4_COLUMNS = [
    ("display_name", "View"),
    ("operation_visible", "Operation"),
    ("effect_visible", "Effect"),
    ("dependency_path_visible", "Dependency"),
    ("trust_boundary_visible", "Trust boundary"),
    ("guard_visible", "Guard"),
    ("context_completeness", "Completeness"),
]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(BASE_DIR).as_posix()
    except ValueError:
        return resolved.as_posix()


def latex_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in text)


def pct(value: Any) -> str:
    try:
        return f"{float(value) * 100:.1f}\\%"
    except (TypeError, ValueError):
        return ""


def normalize_rq3_rows(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in snapshot.get("rq3_case_rows", []):
        rows.append(
            {
                "id": row.get("id", ""),
                "repository": row.get("repository", ""),
                "ecosystem": row.get("ecosystem", ""),
                "behavior": row.get("behavior", ""),
                "sink": row.get("sink", ""),
                "guard_posture": row.get("guard_posture", ""),
                "evidence_mode": row.get("evidence_mode", ""),
                "trust_boundary": row.get("trust_boundary", ""),
            }
        )
    return rows


def normalize_rq4_rows(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for row in snapshot.get("rq4_view_rows", []):
        rows.append(
            {
                "display_name": row.get("display_name", ""),
                "operation_visible": row.get("operation_visible", 0),
                "effect_visible": row.get("effect_visible", 0),
                "dependency_path_visible": row.get("dependency_path_visible", 0),
                "trust_boundary_visible": row.get("trust_boundary_visible", 0),
                "guard_visible": row.get("guard_visible", 0),
                "context_completeness": row.get("context_completeness", 0),
                "primary_limitation": row.get("primary_limitation", ""),
            }
        )
    return rows


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    fieldnames = list(rows[0].keys()) if rows else []
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def latex_tabular(
    rows: list[dict[str, Any]],
    columns: list[tuple[str, str]],
    caption: str,
    label: str,
    align: str,
    percent_fields: set[str] | None = None,
) -> str:
    percent_fields = percent_fields or set()
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        rf"\caption{{{latex_escape(caption)}}}",
        rf"\label{{{label}}}",
        rf"\begin{{tabular}}{{{align}}}",
        r"\toprule",
        " & ".join(latex_escape(header) for _, header in columns) + r" \\",
        r"\midrule",
    ]
    for row in rows:
        values = []
        for key, _ in columns:
            value = pct(row.get(key)) if key in percent_fields else latex_escape(row.get(key, ""))
            values.append(value)
        lines.append(" & ".join(values) + r" \\")
    lines.extend([r"\bottomrule", r"\end{tabular}", r"\end{table}", ""])
    return "\n".join(lines)


def write_tex(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def write_notes(snapshot: dict[str, Any], path: Path) -> None:
    h = snapshot.get("headline_numbers", {})
    lines = [
        "# Paper Table Export Notes",
        "",
        "Generated from `paper_results_snapshot.json`.",
        "",
        "## Required LaTeX package",
        "",
        "```latex",
        "\\usepackage{booktabs}",
        "```",
        "",
        "## Claim boundary",
        "",
        "- These tables are paper-writing artifacts, not final accuracy results.",
        "- RQ3 is qualitative case-study evidence.",
        "- RQ4 is representational ablation evidence, not method precision/recall/F1.",
        "",
        "## Headline",
        "",
        f"- Cases: {h.get('case_count', 0)}",
        f"- Guarded cases: {h.get('guarded_cases', 0)}",
        f"- Security-ADG context completeness: {float(h.get('security_adg_context_completeness', 0)):.1%}",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    snapshot = read_json(args.snapshot)
    rq3_rows = normalize_rq3_rows(snapshot)
    rq4_rows = normalize_rq4_rows(snapshot)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    outputs = {
        "rq3_csv": args.output_dir / "table_rq3_case_study.csv",
        "rq3_tex": args.output_dir / "table_rq3_case_study.tex",
        "rq4_csv": args.output_dir / "table_rq4_guard_ablation.csv",
        "rq4_tex": args.output_dir / "table_rq4_guard_ablation.tex",
        "notes": args.output_dir / "README.md",
    }
    write_csv(rq3_rows, outputs["rq3_csv"])
    write_csv(rq4_rows, outputs["rq4_csv"])
    write_tex(
        outputs["rq3_tex"],
        latex_tabular(
            rq3_rows,
            RQ3_COLUMNS,
            "Representative held-out reproduction-confirmed cases. The table reports qualitative local/source evidence, not final accuracy or vulnerability claims.",
            "tab:rq3_case_study",
            "llllll",
        ),
    )
    write_tex(
        outputs["rq4_tex"],
        latex_tabular(
            rq4_rows,
            RQ4_COLUMNS,
            "Guard-aware representation ablation over reproduction-confirmed held-out cases. Completeness is representational context coverage, not detection accuracy.",
            "tab:rq4_guard_ablation",
            "lrrrrrr",
            percent_fields={"context_completeness"},
        ),
    )
    write_notes(snapshot, outputs["notes"])
    print(
        json.dumps(
            {
                "status": "complete",
                "rq3_rows": len(rq3_rows),
                "rq4_rows": len(rq4_rows),
                "outputs": {name: display_path(path) for name, path in outputs.items()},
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
