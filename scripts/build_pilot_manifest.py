"""Build the fixed five-repository pilot manifest from the frozen corpus."""

from __future__ import annotations

import csv
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
CORPUS = BASE_DIR / "dataset" / "corpus_manifest.csv"
OUTPUT = BASE_DIR / "dataset" / "pilot_manifest.csv"

PILOT_SELECTION = {
    "mantrakp04/manusmcp": {
        "pilot_role": "agent_platform_and_tool_orchestration",
        "experiment_split": "development",
        "use_for_method_tuning": "true",
        "recall_gold_scope": "false",
        "selection_rationale": (
            "Compact TypeScript platform with multiple specialized agents and "
            "external tool orchestration."
        ),
    },
    "SWE-agent/mini-swe-agent": {
        "pilot_role": "coding_and_command_execution",
        "experiment_split": "development",
        "use_for_method_tuning": "true",
        "recall_gold_scope": "false",
        "selection_rationale": (
            "Compact Python coding agent representing shell and repository operations."
        ),
    },
    "dddabtc/winremote-mcp": {
        "pilot_role": "mcp_and_remote_host_control",
        "experiment_split": "held_out_evaluation",
        "use_for_method_tuning": "false",
        "recall_gold_scope": "true",
        "selection_rationale": (
            "Small Python MCP project with a high-impact remote-host security surface."
        ),
    },
    "nexu-io/html-anything": {
        "pilot_role": "browser_and_web_content",
        "experiment_split": "held_out_evaluation",
        "use_for_method_tuning": "false",
        "recall_gold_scope": "true",
        "selection_rationale": (
            "Moderate TypeScript project representing browser/web-content trust boundaries."
        ),
    },
    "microsoft/magentic-ui": {
        "pilot_role": "multi_agent_autogen",
        "experiment_split": "held_out_evaluation",
        "use_for_method_tuning": "false",
        "recall_gold_scope": "false",
        "selection_rationale": (
            "AutoGen-based multi-agent system used to exercise delegation and handoff labels."
        ),
    },
}


def main() -> int:
    with CORPUS.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
        corpus_fields = list(rows[0].keys()) if rows else []

    by_repo = {row["repo"]: row for row in rows}
    missing = sorted(set(PILOT_SELECTION) - set(by_repo))
    if missing:
        raise RuntimeError(f"pilot repositories missing from corpus: {missing}")

    pilot_rows = []
    for repo, pilot_fields in PILOT_SELECTION.items():
        pilot_rows.append({**by_repo[repo], **pilot_fields})

    fields = corpus_fields + [
        "pilot_role",
        "experiment_split",
        "use_for_method_tuning",
        "recall_gold_scope",
        "selection_rationale",
    ]
    temporary = OUTPUT.with_suffix(OUTPUT.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(pilot_rows)
    temporary.replace(OUTPUT)

    print(f"Pilot repositories: {len(pilot_rows)}")
    for row in pilot_rows:
        print(f"  {row['sample_id']} {row['repo']} [{row['pilot_role']}]")
    print(f"Manifest: {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
