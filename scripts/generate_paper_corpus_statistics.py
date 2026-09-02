"""Generate reproducible corpus tables for the AgentSecBench manuscript."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
MANIFEST = BASE_DIR / "dataset" / "corpus_manifest.csv"
OUT_DIR = BASE_DIR / "analysis" / "paper"
AUDIT = OUT_DIR / "corpus_snapshot_audit.json"


def as_int(row: dict, field: str) -> int:
    return int(row[field])


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    head = "| " + " | ".join(headers) + " |"
    rule = "|" + "|".join("---" for _ in headers) + "|"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([head, rule, *body])


def main() -> int:
    with MANIFEST.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    ecosystem = defaultdict(lambda: {"repositories": 0, "source_files": 0, "source_bytes": 0})
    languages = Counter()
    priorities = Counter()
    for row in rows:
        bucket = ecosystem[row["ecosystem"]]
        bucket["repositories"] += 1
        bucket["source_files"] += as_int(row, "source_file_count")
        bucket["source_bytes"] += as_int(row, "source_bytes")
        languages[row["dominant_language"]] += 1
        priorities[row["selection_priority"]] += 1

    manifest_clean_worktrees = sum(row["working_tree_clean"].lower() == "true" for row in rows)
    audit_summary: dict[str, object] = {}
    if AUDIT.exists():
        audit_summary = json.loads(AUDIT.read_text(encoding="utf-8"))

    summary = {
        "repositories": len(rows),
        "ecosystems": len(ecosystem),
        "source_files": sum(as_int(row, "source_file_count") for row in rows),
        "source_bytes": sum(as_int(row, "source_bytes") for row in rows),
        "source_megabytes_decimal": round(sum(as_int(row, "source_bytes") for row in rows) / 1_000_000, 3),
        "frozen_commits": len({row["git_commit"] for row in rows}),
        "manifest_clean_worktrees": manifest_clean_worktrees,
        "current_audit_clean_worktrees": audit_summary.get("currently_verifiable_clean_worktrees"),
        "current_audit_publication_gate": audit_summary.get("publication_gate"),
        "selection_priority": dict(sorted(priorities.items())),
    }
    ecosystem_rows = [
        {"ecosystem": name, **values, "source_megabytes_decimal": round(values["source_bytes"] / 1_000_000, 3)}
        for name, values in ecosystem.items()
    ]
    ecosystem_rows.sort(key=lambda row: (-row["repositories"], row["ecosystem"]))
    language_rows = [
        {"dominant_language": name, "repositories": count,
         "share_percent": round(100 * count / len(rows), 1)}
        for name, count in languages.most_common()
    ]

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "corpus_statistics.json").write_text(
        json.dumps({"summary": summary, "ecosystems": ecosystem_rows, "dominant_languages": language_rows}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    for name, output_rows in (("ecosystem_statistics.csv", ecosystem_rows), ("dominant_language_statistics.csv", language_rows)):
        with (OUT_DIR / name).open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(output_rows[0]))
            writer.writeheader()
            writer.writerows(output_rows)

    overview = markdown_table(
        ["Repositories", "Ecosystems", "Frozen commits", "Source files", "Source size (MB)", "Manifest clean at capture", "Current audit clean"],
        [[str(summary["repositories"]), str(summary["ecosystems"]), str(summary["frozen_commits"]),
          f'{summary["source_files"]:,}', f'{summary["source_megabytes_decimal"]:,.1f}',
          str(summary["manifest_clean_worktrees"]),
          str(summary["current_audit_clean_worktrees"] or "not audited")]]
    )
    ecosystem_table = markdown_table(
        ["Ecosystem", "Repositories", "Source files", "Source size (MB)"],
        [[row["ecosystem"], str(row["repositories"]), f'{row["source_files"]:,}',
          f'{row["source_megabytes_decimal"]:,.1f}'] for row in ecosystem_rows],
    )
    language_table = markdown_table(
        ["Dominant language", "Repositories", "Share"],
        [[row["dominant_language"], str(row["repositories"]), f'{row["share_percent"]:.1f}%'] for row in language_rows],
    )
    manuscript = "# Generated Corpus Tables\n\n## Corpus overview\n\n" + overview + "\n\n## Ecosystem coverage\n\n" + ecosystem_table + "\n\n## Dominant-language distribution\n\n" + language_table + "\n"
    (OUT_DIR / "corpus_tables.md").write_text(manuscript, encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
