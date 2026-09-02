"""Finalize a proposal-plus-human-adjudication case review into paper-ready artifacts."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
REVIEW_DIR = BASE_DIR / "analysis" / "case_review" / "reviews"
OUTPUT_DIR = BASE_DIR / "analysis" / "case_review" / "adjudicated"
STRUCTURED_FIELDS = (
    "reachability",
    "caller_trust",
    "access_control",
    "impacts",
    "case_relation",
    "case_id",
    "merge_into_case_id",
    "final_case_label",
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def canonical_value(field: str, value):
    if field == "impacts":
        return sorted(value or [])
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proposal", default="codex")
    parser.add_argument("--adjudicator", required=True)
    args = parser.parse_args()

    proposal_path = REVIEW_DIR / f"reviewer_{args.proposal.lower()}.jsonl"
    adjudicator_path = REVIEW_DIR / f"reviewer_{args.adjudicator.lower()}.jsonl"
    proposal_rows = read_jsonl(proposal_path)
    human_rows = read_jsonl(adjudicator_path)
    proposal = {row["task_id"]: row for row in proposal_rows}
    human = {row["task_id"]: row for row in human_rows}
    if set(proposal) != set(human):
        raise SystemExit("proposal and adjudicator task sets differ")
    if any(row.get("_status") != "completed" for row in human_rows):
        raise SystemExit("adjudicator file contains incomplete rows")

    findings = []
    semantic_agreement = 0
    raw_agreement = 0
    for task_id in proposal:
        source = proposal[task_id]
        decided = human[task_id]
        raw_equal = all(source.get(field) == decided.get(field) for field in STRUCTURED_FIELDS)
        semantic_equal = all(
            canonical_value(field, source.get(field)) == canonical_value(field, decided.get(field))
            for field in STRUCTURED_FIELDS
        )
        raw_agreement += int(raw_equal)
        semantic_agreement += int(semantic_equal)
        final = {
            key: value
            for key, value in decided.items()
            if key not in {"_saved_at_utc", "_completed_at_utc", "_status"}
        }
        final.update(
            {
                "adjudication_mode": "reviewer_saw_proposal",
                "proposal_reviewer": args.proposal,
                "adjudicator": args.adjudicator,
                "proposal_semantic_agreement": semantic_equal,
                "adjudication_status": "final",
            }
        )
        final["impacts"] = sorted(final.get("impacts", []))
        findings.append(final)

    case_roots: dict[str, dict] = {}
    members: dict[str, list[dict]] = {}
    rejected = []
    for row in findings:
        relation = row["case_relation"]
        if relation == "new_case":
            case_id = row["case_id"]
            if not case_id or case_id in case_roots:
                raise SystemExit(f"invalid or duplicate root case ID for {row['task_id']}")
            case_roots[case_id] = row
            members.setdefault(case_id, []).append(row)
        elif relation == "merge_existing":
            members.setdefault(row["merge_into_case_id"], []).append(row)
        elif relation == "not_security_case":
            rejected.append(row["task_id"])
        else:
            raise SystemExit(f"unresolved relation for {row['task_id']}: {relation}")
    dangling = sorted(set(members) - set(case_roots))
    if dangling:
        raise SystemExit(f"merged findings target missing cases: {dangling}")

    cases = []
    for case_id, root in case_roots.items():
        case_members = members[case_id]
        cases.append(
            {
                "case_id": case_id,
                "case_title": root["case_title"],
                "final_case_label": root["final_case_label"],
                "root_cause": root["root_cause"],
                "member_task_ids": [row["task_id"] for row in case_members],
                "member_candidate_ids": [row["candidate_id"] for row in case_members],
                "finding_count": len(case_members),
                "impacts": sorted({impact for row in case_members for impact in row.get("impacts", [])}),
                "evidence_refs": root["evidence_refs"],
                "rationale": root["rationale"],
                "missing_context": root["missing_context"],
                "adjudicator": args.adjudicator,
                "adjudication_status": "final",
            }
        )

    summary = {
        "proposal_reviewer": args.proposal,
        "adjudicator": args.adjudicator,
        "review_design": "proposal shown to human adjudicator; not independent or blinded",
        "finding_count": len(findings),
        "completed_findings": len(findings),
        "raw_structured_agreement": raw_agreement,
        "semantic_structured_agreement": semantic_agreement,
        "final_label_agreement": sum(
            proposal[task_id]["final_case_label"] == human[task_id]["final_case_label"]
            for task_id in proposal
        ),
        "finding_label_counts": dict(Counter(row["final_case_label"] for row in findings)),
        "case_count": len(cases),
        "case_label_counts": dict(Counter(row["final_case_label"] for row in cases)),
        "rejected_finding_count": len(rejected),
        "rejected_task_ids": rejected,
        "methodological_note": (
            "Agreement here records whether the adjudicator changed a visible proposal. "
            "It must not be reported as independent inter-rater reliability or Fleiss' kappa."
        ),
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUTPUT_DIR / "adjudicated_findings.jsonl", findings)
    write_jsonl(OUTPUT_DIR / "adjudicated_cases.jsonl", cases)
    (OUTPUT_DIR / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
