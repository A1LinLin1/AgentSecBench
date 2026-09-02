"""Analyze a completed model-assisted human audit without treating it as ground truth.

The script produces reproducible JSON/CSV summaries and a canonical Data
Analytics report artifact.  It intentionally reports alignment, not accuracy:
the reviewer saw the model votes while auditing.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
RUN_DIR = BASE_DIR / "annotations" / "model_annotation" / "runs" / "panel_v3_hybrid"
DEFAULT_AUDIT = (
    BASE_DIR / "annotations" / "model_audit" / "reviewers" / "reviewer_reviewer03.jsonl"
)
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "model_audit" / "reviewer03"
PROVIDERS = ("openai", "anthropic", "gemini", "qwen", "deepseek")
FIELD_LABELS = {
    "agent_relevant": "Agent relevance",
    "behavior_confirmed": "Behavior confirmed",
    "dependency_confirmed": "Dependency confirmed",
    "effect_type": "Effect type",
    "guard_effective": "Guard effectiveness",
    "guard_present": "Guard present",
    "label_confidence": "Label confidence",
    "source_external": "External source",
    "source_type": "Source type",
    "trust_boundary_crossed": "Trust boundary",
    "vulnerability_status": "Vulnerability status",
    "weakness_present": "Weakness present",
}


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def percentage(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def source(source_id: str, label: str, path: str) -> dict:
    return {"id": source_id, "label": label, "path": path}


def query_source(source_id: str, label: str, path: str, sql: str) -> dict:
    return {
        "id": source_id,
        "label": label,
        "path": path,
        "query": {
            "engine": "sqlite",
            "language": "sql",
            "sql": sql,
            "description": label,
            "tables_used": ["field_summary" if "field_summary" in sql else "provider_alignment"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit", type=Path, default=DEFAULT_AUDIT)
    parser.add_argument("--run-dir", type=Path, default=RUN_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    audit_path = args.audit.resolve()
    run_dir = args.run_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    audit_rows = read_jsonl(audit_path)
    if len(audit_rows) != 150:
        raise SystemExit(f"expected 150 audit rows, found {len(audit_rows)}")
    audit_by_task = {row["task_id"]: row for row in audit_rows}
    if len(audit_by_task) != len(audit_rows):
        raise SystemExit("duplicate task IDs in audit file")
    incomplete = [row["task_id"] for row in audit_rows if row.get("_status") != "completed"]
    if incomplete:
        raise SystemExit(f"incomplete audit tasks: {incomplete}")
    if any(row.get("review_type") != "model_assisted_audit" for row in audit_rows):
        raise SystemExit("audit contains a non-model-assisted review row")

    fields = list(FIELD_LABELS)
    model_rows: dict[str, dict[str, dict]] = {}
    for provider in PROVIDERS:
        path = run_dir / "normalized" / f"{provider}.jsonl"
        rows = read_jsonl(path)
        by_task = {row["task_id"]: row["annotation"] for row in rows}
        if set(by_task) != set(audit_by_task):
            missing = sorted(set(audit_by_task) - set(by_task))
            extra = sorted(set(by_task) - set(audit_by_task))
            raise SystemExit(f"{provider} task mismatch: missing={missing}, extra={extra}")
        model_rows[provider] = by_task

    alignment_counts = Counter(row["panel_alignment"] for row in audit_rows)
    final_label_counts = {field: Counter(row.get(field) for row in audit_rows) for field in fields}

    field_rows: list[dict] = []
    provider_field_matches: dict[str, dict[str, list[bool]]] = {
        provider: defaultdict(list) for provider in PROVIDERS
    }
    strength_counts: dict[int, Counter] = defaultdict(Counter)
    task_rows: list[dict] = []

    for row in audit_rows:
        task_id = row["task_id"]
        unique_fields = 0
        unique_matches = 0
        tie_fields = len(row.get("panel_tied_fields", []))
        override_fields = list(row.get("overridden_plurality_fields", []))
        for field in fields:
            human_value = row.get(field)
            votes = [model_rows[provider][task_id].get(field) for provider in PROVIDERS]
            counts = Counter(votes)
            top_count = max(counts.values())
            plurality = row["panel_plurality"].get(field)
            if plurality is not None:
                unique_fields += 1
                matched = human_value == plurality
                unique_matches += int(matched)
                strength_counts[top_count]["eligible"] += 1
                strength_counts[top_count]["matched"] += int(matched)
            for provider, model_value in zip(PROVIDERS, votes):
                provider_field_matches[provider][field].append(model_value == human_value)
        task_rows.append(
            {
                "task_id": task_id,
                "candidate_id": row["candidate_id"],
                "panel_alignment": row["panel_alignment"],
                "unique_plurality_fields": unique_fields,
                "unique_plurality_matches": unique_matches,
                "tied_fields": tie_fields,
                "overridden_fields": len(override_fields),
                "overridden_field_names": ";".join(override_fields),
                "behavior_confirmed": row.get("behavior_confirmed"),
                "agent_relevant": row.get("agent_relevant"),
                "weakness_present": row.get("weakness_present"),
                "vulnerability_status": row.get("vulnerability_status"),
            }
        )

    for field in fields:
        eligible = [row for row in audit_rows if row["panel_plurality"].get(field) is not None]
        matches = sum(row.get(field) == row["panel_plurality"].get(field) for row in eligible)
        ties = sum(field in row.get("panel_tied_fields", []) for row in audit_rows)
        field_rows.append(
            {
                "field": field,
                "field_label": FIELD_LABELS[field],
                "tasks": len(audit_rows),
                "unique_plurality_n": len(eligible),
                "unique_plurality_matches": matches,
                "unique_plurality_overrides": len(eligible) - matches,
                "unique_plurality_match_rate": percentage(matches, len(eligible)),
                "unique_plurality_override_rate": percentage(len(eligible) - matches, len(eligible)),
                "tie_n": ties,
                "tie_rate": percentage(ties, len(audit_rows)),
            }
        )

    provider_rows: list[dict] = []
    for provider in PROVIDERS:
        all_matches = [
            matched
            for field in fields
            for matched in provider_field_matches[provider][field]
        ]
        provider_rows.append(
            {
                "provider": provider,
                "field_comparisons": len(all_matches),
                "matches": sum(all_matches),
                "alignment_rate": percentage(sum(all_matches), len(all_matches)),
            }
        )

    strength_rows = [
        {
            "top_vote_count": strength,
            "vote_fraction": strength / len(PROVIDERS),
            "unique_plurality_comparisons": counts["eligible"],
            "matches": counts["matched"],
            "overrides": counts["eligible"] - counts["matched"],
            "match_rate": percentage(counts["matched"], counts["eligible"]),
        }
        for strength, counts in sorted(strength_counts.items())
    ]

    completed_at = max(row["_completed_at_utc"] for row in audit_rows)
    total_unique = sum(row["unique_plurality_n"] for row in field_rows)
    total_unique_matches = sum(row["unique_plurality_matches"] for row in field_rows)
    summary = {
        "analysis_type": "descriptive_model_assisted_audit",
        "interpretation": (
            "Alignment with a model-assisted reviewer; not model accuracy, independent human "
            "agreement, ground truth, or a gold-standard evaluation."
        ),
        "reviewer": audit_rows[0]["reviewer"],
        "panel_run_id": audit_rows[0]["model_panel_run_id"],
        "tasks": len(audit_rows),
        "models": len(PROVIDERS),
        "model_annotations": len(audit_rows) * len(PROVIDERS),
        "audit_completed_at_utc": completed_at,
        "panel_alignment_counts": dict(alignment_counts),
        "panel_alignment_rates": {
            key: percentage(alignment_counts[key], len(audit_rows))
            for key in ("accepted_plurality", "resolved_ties_only", "modified_plurality")
        },
        "unique_plurality_field_comparisons": total_unique,
        "unique_plurality_field_matches": total_unique_matches,
        "unique_plurality_field_overrides": total_unique - total_unique_matches,
        "unique_plurality_field_match_rate": percentage(total_unique_matches, total_unique),
        "final_label_counts": {
            field: {str(key): value for key, value in sorted(counts.items(), key=lambda item: str(item[0]))}
            for field, counts in final_label_counts.items()
        },
        "field_summary": field_rows,
        "provider_alignment": provider_rows,
        "vote_strength_summary": strength_rows,
        "limitations": [
            "The reviewer saw all five model labels and rationales before finalizing each task.",
            "The reviewer is not an independent annotator; alignment is not an accuracy estimate.",
            "Only one completed model-assisted reviewer is available.",
            "No independent human gold set or adjudicated ground truth is currently available.",
        ],
    }

    write_json(output_dir / "summary.json", summary)
    write_csv(output_dir / "field_summary.csv", field_rows)
    write_csv(output_dir / "provider_alignment.csv", provider_rows)
    write_csv(output_dir / "vote_strength_summary.csv", strength_rows)
    write_csv(output_dir / "task_summary.csv", task_rows)

    database_path = output_dir / "report_data.sqlite"
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("DROP TABLE IF EXISTS field_summary")
        connection.execute("DROP TABLE IF EXISTS provider_alignment")
        connection.execute(
            """
            CREATE TABLE field_summary (
                field TEXT PRIMARY KEY,
                field_label TEXT NOT NULL,
                tasks INTEGER NOT NULL,
                unique_plurality_n INTEGER NOT NULL,
                unique_plurality_matches INTEGER NOT NULL,
                unique_plurality_overrides INTEGER NOT NULL,
                unique_plurality_match_rate REAL NOT NULL,
                unique_plurality_override_rate REAL NOT NULL,
                tie_n INTEGER NOT NULL,
                tie_rate REAL NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE provider_alignment (
                provider TEXT PRIMARY KEY,
                field_comparisons INTEGER NOT NULL,
                matches INTEGER NOT NULL,
                alignment_rate REAL NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO field_summary VALUES (:field, :field_label, :tasks, :unique_plurality_n, "
            ":unique_plurality_matches, :unique_plurality_overrides, :unique_plurality_match_rate, "
            ":unique_plurality_override_rate, :tie_n, :tie_rate)",
            field_rows,
        )
        connection.executemany(
            "INSERT INTO provider_alignment VALUES (:provider, :field_comparisons, :matches, :alignment_rate)",
            provider_rows,
        )
        connection.commit()
        field_query = (
            "SELECT field, field_label, tasks, unique_plurality_n, unique_plurality_matches, "
            "unique_plurality_overrides, unique_plurality_match_rate, unique_plurality_override_rate, "
            "tie_n, tie_rate FROM field_summary ORDER BY unique_plurality_override_rate DESC, field_label"
        )
        provider_query = (
            "SELECT provider, field_comparisons, matches, alignment_rate "
            "FROM provider_alignment ORDER BY alignment_rate DESC, provider"
        )
        connection.row_factory = sqlite3.Row
        chart_fields = [dict(row) for row in connection.execute(field_query)]
        provider_chart = [dict(row) for row in connection.execute(provider_query)]
    finally:
        connection.close()

    generated_at = datetime.now(timezone.utc).isoformat()
    vulnerability_counts = final_label_counts["vulnerability_status"]
    source_audit_id = "assisted_audit"
    source_panel_id = "model_panel"
    source_script_id = "analysis_script"
    field_query_source_id = "field_summary_query"
    provider_query_source_id = "provider_alignment_query"
    field_source = query_source(
        field_query_source_id,
        "SQLite field-level audit summary query",
        "analysis/model_audit/reviewer03/report_data.sqlite",
        field_query,
    )
    provider_source = query_source(
        provider_query_source_id,
        "SQLite provider-alignment summary query",
        "analysis/model_audit/reviewer03/report_data.sqlite",
        provider_query,
    )

    artifact = {
        "surface": "report",
        "manifest": {
            "version": 1,
            "surface": "report",
            "title": "Model-Assisted Audit: Preliminary Alignment Analysis",
            "description": "Descriptive analysis of one completed assisted audit over 150 security-behavior candidates.",
            "generatedAt": generated_at,
            "filters": [],
            "cards": [],
            "charts": [
                {
                    "id": "field_override_chart",
                    "title": "Unique-plurality override rate by field",
                    "subtitle": "150 tasks; denominator excludes tied model pluralities for each field.",
                    "type": "bar",
                    "dataset": "field_summary",
                    "sourceId": field_query_source_id,
                    "valueFormat": "percent",
                    "encodings": {
                        "x": {"field": "field_label", "type": "nominal", "label": "Audit field"},
                        "y": {
                            "field": "unique_plurality_override_rate",
                            "type": "quantitative",
                            "label": "Override rate",
                        },
                        "tooltip": [
                            {"field": "unique_plurality_n", "type": "quantitative", "label": "Unique pluralities"},
                            {"field": "unique_plurality_overrides", "type": "quantitative", "label": "Overrides"},
                            {"field": "tie_n", "type": "quantitative", "label": "Ties"},
                        ],
                    },
                },
                {
                    "id": "provider_alignment_chart",
                    "title": "Model-to-assisted-reviewer field alignment",
                    "subtitle": "1,800 categorical comparisons per model; descriptive only, not model accuracy.",
                    "type": "bar",
                    "dataset": "provider_alignment",
                    "sourceId": provider_query_source_id,
                    "valueFormat": "percent",
                    "encodings": {
                        "x": {"field": "provider", "type": "nominal", "label": "Model panel member"},
                        "y": {"field": "alignment_rate", "type": "quantitative", "label": "Alignment rate"},
                        "tooltip": [
                            {"field": "matches", "type": "quantitative", "label": "Matches"},
                            {"field": "field_comparisons", "type": "quantitative", "label": "Comparisons"},
                        ],
                    },
                },
            ],
            "tables": [
                {
                    "id": "field_table",
                    "title": "Field-level plurality alignment",
                    "subtitle": "Exact counts for unique pluralities, overrides, and ties.",
                    "dataset": "field_summary",
                    "sourceId": field_query_source_id,
                    "defaultSort": {"field": "unique_plurality_override_rate", "direction": "desc"},
                    "columns": [
                        {"field": "field_label", "label": "Field", "type": "text"},
                        {"field": "unique_plurality_n", "label": "Unique plurality", "format": "number"},
                        {"field": "unique_plurality_overrides", "label": "Overrides", "format": "number"},
                        {"field": "unique_plurality_override_rate", "label": "Override rate", "format": "percent"},
                        {"field": "tie_n", "label": "Ties", "format": "number"},
                    ],
                }
            ],
            "sources": [
                source(source_audit_id, "Completed reviewer03 model-assisted audit", "annotations/model_audit/reviewers/reviewer_reviewer03.jsonl"),
                source(source_panel_id, "Frozen panel_v3_hybrid normalized model outputs", "annotations/model_annotation/runs/panel_v3_hybrid/normalized/"),
                source(source_script_id, "Reproducible audit analysis", "scripts/analyze_model_audit.py"),
                source(field_query_source_id, "SQLite field-level audit summary query", "analysis/model_audit/reviewer03/report_data.sqlite"),
                source(provider_query_source_id, "SQLite provider-alignment summary query", "analysis/model_audit/reviewer03/report_data.sqlite"),
            ],
            "blocks": [
                {"id": "title", "type": "markdown", "body": "# Model-Assisted Audit: Preliminary Alignment Analysis"},
                {
                    "id": "technical_summary",
                    "type": "markdown",
                    "sourceId": source_script_id,
                    "body": (
                        "## Technical summary\n\n"
                        f"- **All {len(audit_rows)} tasks were completed and matched to all five model outputs.** "
                        f"The audit contains {len(audit_rows) * len(PROVIDERS):,} frozen model annotations.\n"
                        f"- **The reviewer modified a unique panel plurality on {alignment_counts['modified_plurality']} tasks "
                        f"({percentage(alignment_counts['modified_plurality'], len(audit_rows)):.1%}).** "
                        f"Another {alignment_counts['resolved_ties_only']} tasks required only tie resolution.\n"
                        f"- **Final audit labels contain {vulnerability_counts.get('confirmed', 0)} confirmed and "
                        f"{vulnerability_counts.get('candidate', 0)} candidate vulnerability statuses.** "
                        "These remain assisted-review outcomes, not independently adjudicated vulnerabilities.\n"
                        "- **The evidence is ready for model-error analysis, but not for Precision/Recall/F1 claims.** "
                        "Independent blind annotation and adjudication are still required for a Gold Set."
                    ),
                },
                {
                    "id": "field_result_text",
                    "type": "markdown",
                    "sourceId": source_script_id,
                    "body": (
                        "## Overrides were rare and concentrated in four fields\n\n"
                        f"Across {total_unique:,} field-level comparisons with a unique model plurality, "
                        f"the assisted reviewer changed {total_unique - total_unique_matches} labels "
                        f"({percentage(total_unique - total_unique_matches, total_unique):.2%}). "
                        "The chart separates this from ties, where no unique model plurality existed. "
                        "Because the reviewer saw the model panel, the low override rate is evidence about the "
                        "audit workflow, not independent validation of model correctness."
                    ),
                },
                {"id": "field_chart", "type": "chart", "chartId": "field_override_chart"},
                {"id": "field_table_block", "type": "table", "tableId": "field_table"},
                {
                    "id": "provider_result_text",
                    "type": "markdown",
                    "sourceId": source_script_id,
                    "body": (
                        "## Individual models aligned differently with the assisted final labels\n\n"
                        "Each model is compared with the reviewer's final value on the same 12 categorical fields "
                        "for all 150 tasks. This ranking is useful for locating model-specific disagreement cases, "
                        "but it is not an accuracy leaderboard: the reviewer could see and accept these same model outputs."
                    ),
                },
                {"id": "provider_chart", "type": "chart", "chartId": "provider_alignment_chart"},
                {
                    "id": "scope",
                    "type": "markdown",
                    "body": (
                        "## Scope and metric definitions\n\n"
                        "- **Task population:** the frozen 150-task pilot sampled from static-scan candidates.\n"
                        "- **Unique-plurality match:** the assisted reviewer selected the same value as the single "
                        "highest-vote model label for a field; tied fields are excluded from this denominator.\n"
                        "- **Task alignment:** `accepted_plurality` means no unique plurality was overridden; "
                        "`resolved_ties_only` means the reviewer only resolved tied fields; `modified_plurality` "
                        "means at least one unique plurality was changed.\n"
                        "- **Provider alignment:** exact categorical agreement between one model and the assisted "
                        "reviewer's final label across 150 tasks × 12 fields."
                    ),
                },
                {
                    "id": "methodology",
                    "type": "markdown",
                    "sourceId": source_script_id,
                    "body": (
                        "## Reproducible methodology\n\n"
                        "The analysis validates 150 unique completed task IDs, verifies one-to-one coverage in each "
                        "of the five normalized model files, recomputes exact-match and plurality statistics from "
                        "the frozen categorical labels, and exports task-, field-, provider-, and vote-strength-level tables. "
                        "Run `python scripts/analyze_model_audit.py` from the repository root to reproduce the outputs."
                    ),
                },
                {
                    "id": "limitations",
                    "type": "markdown",
                    "body": (
                        "## Limitations prevent accuracy or Gold-Set claims\n\n"
                        "1. The reviewer saw all five model labels and rationales, so reviewer decisions are not independent.\n"
                        "2. Only one model-assisted reviewer completed the full task set.\n"
                        "3. The 150 tasks are a stratified pilot sample of scanner candidates, not confirmed vulnerabilities.\n"
                        "4. Fleiss' κ from the five-model panel measures inter-model agreement only; it does not measure human reliability.\n"
                        "5. Precision, Recall, and F1 remain undefined until blind human labels are adjudicated into a Gold Set."
                    ),
                },
                {
                    "id": "next_steps",
                    "type": "markdown",
                    "body": (
                        "## Recommended next steps\n\n"
                        "1. Use the assisted audit to select high-value disagreement cases for qualitative model-error analysis.\n"
                        "2. When independent annotators become available, freeze at least two blind label sets and compute Cohen's κ; "
                        "use three complete blind label sets for Fleiss' κ.\n"
                        "3. Adjudicate blind disagreements with written source-code rationales to form the Gold Set.\n"
                        "4. Only then evaluate the current scanner, Semgrep, CodeQL, and the proposed semantic method with Precision, Recall, and F1."
                    ),
                },
                {
                    "id": "questions",
                    "type": "markdown",
                    "body": (
                        "## Further questions\n\n"
                        "- Do the five plurality overrides share a behavior type, repository family, or missing-context pattern?\n"
                        "- Are the two `confirmed` vulnerability-status outcomes supported by complete cross-file evidence?\n"
                        "- Which disagreement strata should be prioritized for the first independent annotation batch?"
                    ),
                },
            ],
        },
        "snapshot": {
            "version": 1,
            "generatedAt": generated_at,
            "status": "ready",
            "datasets": {
                "field_summary": chart_fields,
                "provider_alignment": provider_chart,
            },
            "accessIssues": [],
        },
        "sources": [
            source(source_audit_id, "Completed reviewer03 model-assisted audit", "annotations/model_audit/reviewers/reviewer_reviewer03.jsonl"),
            source(source_panel_id, "Frozen panel_v3_hybrid normalized model outputs", "annotations/model_annotation/runs/panel_v3_hybrid/normalized/"),
            source(source_script_id, "Reproducible audit analysis", "scripts/analyze_model_audit.py"),
            field_source,
            provider_source,
        ],
    }
    write_json(output_dir / "report_artifact.json", artifact)

    print(json.dumps({
        "output_dir": str(output_dir),
        "tasks": len(audit_rows),
        "alignment_counts": dict(alignment_counts),
        "unique_plurality_field_overrides": total_unique - total_unique_matches,
        "vulnerability_status": summary["final_label_counts"]["vulnerability_status"],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
