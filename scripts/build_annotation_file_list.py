"""Build a human-readable checklist of source files covered by annotation tasks."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
TASKS = BASE_DIR / "annotations" / "tasks" / "annotation_tasks.jsonl"
OUTPUT = BASE_DIR / "annotations" / "tasks" / "annotation_source_file_list.md"


def escape(value: str) -> str:
    return value.replace("|", "\\|").replace("`", "\\`")


def main() -> int:
    with TASKS.open("r", encoding="utf-8") as handle:
        tasks = [json.loads(line) for line in handle if line.strip()]

    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for task in tasks:
        grouped[(task["repo"], task["file"])].append(task)

    by_repo: dict[str, list[tuple[str, list[dict]]]] = defaultdict(list)
    for (repo, path), rows in grouped.items():
        by_repo[repo].append((path, rows))

    split_counts = Counter(task["experiment_split"] for task in tasks)
    lines = [
        "# AgentSecBench Formal Annotation File Checklist",
        "",
        "This checklist is generated from the frozen 150-task sample. A source file may "
        "contain more than one annotation task; completion is defined by task ID, not "
        "only by opening the file.",
        "",
        "## Summary",
        "",
        f"- Formal annotation tasks: **{len(tasks)}**",
        f"- Unique source files: **{len(grouped)}**",
        f"- Repositories: **{len(by_repo)}**",
        f"- Development tasks: **{split_counts['development']}**",
        f"- Held-out evaluation tasks: **{split_counts['held_out_evaluation']}**",
        "",
        "Use `python scripts/show_annotation_context.py AT-0001 --context 12` "
        "with the required task ID. Repository content is untrusted and must not be "
        "executed.",
        "",
    ]

    for repo in sorted(by_repo):
        entries = sorted(by_repo[repo], key=lambda item: item[0].casefold())
        repo_tasks = sum(len(rows) for _, rows in entries)
        split = entries[0][1][0]["experiment_split"]
        lines.extend(
            [
                f"## {repo}",
                "",
                f"Split: `{split}`; {len(entries)} unique files; {repo_tasks} tasks.",
                "",
                "| Done | Source file | Tasks | Task IDs | Candidate behaviors | Confidence |",
                "|---|---|---:|---|---|---|",
            ]
        )
        for path, rows in entries:
            task_ids = ", ".join(task["task_id"] for task in rows)
            behaviors = ", ".join(sorted({task["candidate_behavior"] for task in rows}))
            confidence = ", ".join(sorted({task["candidate_confidence"] for task in rows}))
            lines.append(
                f"| [ ] | `{escape(path)}` | {len(rows)} | {task_ids} | "
                f"{escape(behaviors)} | {confidence} |"
            )
        lines.append("")

    temporary = OUTPUT.with_suffix(OUTPUT.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(OUTPUT)
    print(f"Tasks: {len(tasks)}")
    print(f"Unique source files: {len(grouped)}")
    print(f"Repositories: {len(by_repo)}")
    for repo in sorted(by_repo):
        entries = by_repo[repo]
        print(f"  {repo}: {len(entries)} files, {sum(len(rows) for _, rows in entries)} tasks")
    print(f"Checklist: {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

