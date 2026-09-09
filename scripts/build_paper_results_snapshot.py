#!/usr/bin/env python3
"""Build a compact paper-results snapshot from local experiment artifacts.

The snapshot is a writing aid. It does not create new labels, does not tune the
method, and does not turn local reproduction evidence into vulnerability or
population-level accuracy claims.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MATRIX = BASE_DIR / "analysis" / "reproduction" / "case_matrix" / "heldout_reproduction_case_matrix.json"
DEFAULT_ABLATION = BASE_DIR / "analysis" / "reproduction" / "guard_ablation" / "guard_ablation_summary.json"
DEFAULT_OUTPUT_DIR = BASE_DIR / "analysis" / "paper_results"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(BASE_DIR).as_posix()
    except ValueError:
        return resolved.as_posix()


def md_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", "<br>")


def pct(value: float) -> str:
    return f"{value:.1%}"


def compact_path(path: str, max_parts: int = 5) -> str:
    parts = [part.strip() for part in str(path).split(" -> ") if part.strip()]
    if len(parts) <= max_parts:
        return " -> ".join(parts)
    head = parts[:2]
    tail = parts[-2:]
    return " -> ".join([*head, "...", *tail])


def build_snapshot(matrix: dict[str, Any], ablation: dict[str, Any]) -> dict[str, Any]:
    rows = matrix.get("rows", [])
    view_rows = ablation.get("view_rows", [])
    by_view = {row["view"]: row for row in view_rows}
    guarded_cases = matrix.get("guard_postures", {}).get("guarded", 0)
    no_guard_cases = matrix.get("guard_postures", {}).get("no_guard_confirmed", 0)
    return {
        "schema_version": "1.0",
        "purpose": "paper writing snapshot from local held-out reproduction evidence; not final evaluation metrics",
        "inputs": {
            "case_matrix_purpose": matrix.get("purpose", ""),
            "ablation_purpose": ablation.get("purpose", ""),
        },
        "headline_numbers": {
            "case_count": matrix.get("case_count", len(rows)),
            "confirmed_behavior_cases": matrix.get("status_groups", {}).get("confirmed_behavior", 0),
            "guarded_cases": guarded_cases,
            "no_guard_confirmed_cases": no_guard_cases,
            "repositories": matrix.get("repositories", {}),
            "ecosystems": matrix.get("ecosystems", {}),
            "behavior_families": matrix.get("behavior_families", {}),
            "sink_only_context_completeness": by_view.get("sink_only", {}).get("context_completeness", 0),
            "plain_adg_context_completeness": by_view.get("plain_adg", {}).get("context_completeness", 0),
            "security_adg_context_completeness": by_view.get("security_adg", {}).get("context_completeness", 0),
            "sink_only_guard_visible": by_view.get("sink_only", {}).get("guard_visible", 0),
            "plain_adg_guard_visible": by_view.get("plain_adg", {}).get("guard_visible", 0),
            "security_adg_guard_visible": by_view.get("security_adg", {}).get("guard_visible", 0),
        },
        "rq3_case_rows": [
            {
                "id": row["id"],
                "repository": row["repository"],
                "ecosystem": row["ecosystem"],
                "behavior": row["behavior_family"],
                "sink": row["sink_family"],
                "trust_boundary": row["trust_boundary"],
                "guard_posture": row["guard_posture"],
                "evidence_mode": row["evidence_mode"],
                "dependency_path": row["dependency_path"],
                "claim_boundary": row["claim_boundary"],
                "not_claimed": row["not_claimed"],
            }
            for row in rows
        ],
        "rq4_view_rows": view_rows,
        "claim_boundaries": [
            "The held-out reproduction set is local/source evidence only, not a held-out gold set.",
            "Do not report precision, recall, F1, or prevalence from these cases alone.",
            "A case marked confirmed_behavior means a security-sensitive behavior path was confirmed under the recorded local/source procedure.",
            "A guarded case means guard context was preserved in evidence; it does not prove the guard is complete or vulnerability-preventing.",
            "CVE/advisory claims require maintainer-confirmed security boundaries, affected versions, and coordinated disclosure.",
        ],
        "recommended_paper_placement": {
            "rq3": "Qualitative case study: real-world behaviors beyond predefined sinks.",
            "rq4": "Representation ablation: sink-only vs simplified ADG vs Security-ADG context preservation.",
            "appendix": "Reproducibility commands and claim-boundary table.",
        },
    }


def write_overview(snapshot: dict[str, Any], path: Path) -> None:
    h = snapshot["headline_numbers"]
    lines = [
        "# Paper Results Snapshot",
        "",
        "This directory is generated from local experiment artifacts. It is a writing aid, not a final evaluation report.",
        "",
        "## Headline numbers",
        "",
        f"- Held-out reproduction-confirmed cases: {h['case_count']}",
        f"- Confirmed behavior cases: {h['confirmed_behavior_cases']}",
        f"- Guarded cases: {h['guarded_cases']}",
        f"- No-guard-confirmed cases: {h['no_guard_confirmed_cases']}",
        f"- Repositories: {', '.join(f'{k}={v}' for k, v in h['repositories'].items())}",
        f"- Ecosystems: {', '.join(f'{k}={v}' for k, v in h['ecosystems'].items())}",
        "",
        "## RQ4 representation headline",
        "",
        f"- Sink-only context completeness: {pct(h['sink_only_context_completeness'])}",
        f"- Simplified ADG context completeness: {pct(h['plain_adg_context_completeness'])}",
        f"- Security-ADG context completeness: {pct(h['security_adg_context_completeness'])}",
        f"- Guard visibility: sink-only {h['sink_only_guard_visible']}, simplified ADG {h['plain_adg_guard_visible']}, Security-ADG {h['security_adg_guard_visible']}",
        "",
        "## Suggested paper sentence",
        "",
        (
            f"Across {h['case_count']} reproduction-confirmed held-out cases, sink-only and simplified ADG views expose "
            f"{h['sink_only_guard_visible']}/{h['guarded_cases']} and {h['plain_adg_guard_visible']}/{h['guarded_cases']} observed guard contexts, respectively, "
            f"while Security-ADG preserves {h['security_adg_guard_visible']}/{h['guarded_cases']} guard contexts and raises representation completeness "
            f"from {pct(h['sink_only_context_completeness'])} / {pct(h['plain_adg_context_completeness'])} to {pct(h['security_adg_context_completeness'])}."
        ),
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_rq3(snapshot: dict[str, Any], path: Path) -> None:
    lines = [
        "# RQ3 Case Study Table",
        "",
        "Use this table for qualitative evidence of real-world security-sensitive Agent behaviors. Do not cite it as prevalence or accuracy.",
        "",
        "| Case | Repository | Ecosystem | Behavior | Sink | Guard | Evidence | Boundary |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in snapshot["rq3_case_rows"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    md_escape(row["id"]),
                    md_escape(row["repository"]),
                    md_escape(row["ecosystem"]),
                    md_escape(row["behavior"]),
                    md_escape(row["sink"]),
                    md_escape(row["guard_posture"]),
                    md_escape(row["evidence_mode"]),
                    md_escape(row["trust_boundary"]),
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## Compact dependency paths",
            "",
            "| Case | Path |",
            "| --- | --- |",
        ]
    )
    for row in snapshot["rq3_case_rows"]:
        lines.append(f"| {md_escape(row['id'])} | {md_escape(compact_path(row['dependency_path']))} |")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_rq4(snapshot: dict[str, Any], path: Path) -> None:
    lines = [
        "# RQ4 Guard-aware Ablation Table",
        "",
        "This table compares representational context, not detection accuracy.",
        "",
        "| View | Operation | Effect | Dependency | Trust boundary | Guard | Context completeness | Main limitation |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in snapshot["rq4_view_rows"]:
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
                    pct(row["context_completeness"]),
                    md_escape(row["primary_limitation"]),
                ]
            )
            + " |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_boundaries(snapshot: dict[str, Any], path: Path) -> None:
    lines = [
        "# Experiment Claim Boundaries",
        "",
        "Use this file as a guardrail while drafting the paper.",
        "",
        "## Allowed claims",
        "",
        "- The local/source reproduction evidence confirms security-sensitive behavior paths for the listed cases.",
        "- Security-ADG preserves dependency, trust-boundary, and guard context that sink-only and simplified ADG views do not represent.",
        "- Guarded cases demonstrate that the representation can retain defensive context rather than merely matching dangerous APIs.",
        "",
        "## Not allowed from this artifact alone",
        "",
    ]
    lines.extend(f"- {boundary}" for boundary in snapshot["claim_boundaries"])
    lines.extend(
        [
            "",
            "## Placement",
            "",
        ]
    )
    for key, value in snapshot["recommended_paper_placement"].items():
        lines.append(f"- {key.upper()}: {value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_commands(args: argparse.Namespace, outputs: dict[str, Path], path: Path) -> None:
    lines = [
        "# Reproducibility Commands",
        "",
        "Run from the repository root.",
        "",
        "## Refresh local held-out evidence summaries",
        "",
        "```powershell",
        "python scripts\\summarize_heldout_reproduction_evidence.py",
        "python scripts\\build_heldout_reproduction_case_matrix.py",
        "python scripts\\build_guard_ablation_table.py",
        "python scripts\\build_paper_results_snapshot.py",
        "```",
        "",
        "## Validate held-out protocol state",
        "",
        "```powershell",
        "python scripts\\validate_heldout_evaluation.py --allow-pending-labels",
        "```",
        "",
        "Expected until the second blinded reviewer finishes:",
        "",
        "```text",
        "status: PASS_PENDING_LABELS",
        "missing: annotations/recall_inventory/reviewer_b_labels.jsonl",
        "```",
        "",
        "## Current snapshot inputs",
        "",
        f"- Case matrix: `{display_path(args.matrix)}`",
        f"- Guard ablation: `{display_path(args.ablation)}`",
        "",
        "## Generated files",
        "",
    ]
    for name, output in outputs.items():
        lines.append(f"- {name}: `{display_path(output)}`")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--ablation", type=Path, default=DEFAULT_ABLATION)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    matrix = read_json(args.matrix)
    ablation = read_json(args.ablation)
    snapshot = build_snapshot(matrix, ablation)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "snapshot_json": args.output_dir / "paper_results_snapshot.json",
        "overview": args.output_dir / "README.md",
        "rq3": args.output_dir / "rq3_case_study_table.md",
        "rq4": args.output_dir / "rq4_guard_ablation_table.md",
        "boundaries": args.output_dir / "experiment_claim_boundaries.md",
        "commands": args.output_dir / "reproducibility_commands.md",
    }
    outputs["snapshot_json"].write_text(json.dumps(snapshot, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    write_overview(snapshot, outputs["overview"])
    write_rq3(snapshot, outputs["rq3"])
    write_rq4(snapshot, outputs["rq4"])
    write_boundaries(snapshot, outputs["boundaries"])
    write_commands(args, outputs, outputs["commands"])
    print(
        json.dumps(
            {
                "status": "complete",
                "cases": snapshot["headline_numbers"]["case_count"],
                "guarded_cases": snapshot["headline_numbers"]["guarded_cases"],
                "security_adg_context_completeness": snapshot["headline_numbers"]["security_adg_context_completeness"],
                "outputs": {name: display_path(path) for name, path in outputs.items()},
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
