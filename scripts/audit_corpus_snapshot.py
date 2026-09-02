"""Audit AgentSecBench manifest uniqueness and locally verifiable frozen snapshots."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
from collections import Counter
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = BASE_DIR / "dataset" / "corpus_manifest.csv"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "paper" / "corpus_snapshot_audit.json"


def git(path: Path, *args: str) -> tuple[int, str]:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={path.as_posix()}", "-C", str(path), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.returncode, result.stdout.strip()


def duplicates(rows: list[dict], field: str) -> list[str]:
    counts = Counter(row[field] for row in rows)
    return sorted(value for value, count in counts.items() if count > 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))

    issues = []
    for row in rows:
        repo = (BASE_DIR / row["repository_path"]).resolve()
        base = {"sample_id": row["sample_id"], "repo": row["repo"], "repository_path": row["repository_path"]}
        if not repo.exists():
            issues.append({**base, "issue": "missing_path"})
            continue
        code, inside = git(repo, "rev-parse", "--is-inside-work-tree")
        if code or inside != "true":
            issues.append({**base, "issue": "not_worktree"})
            continue
        code, head = git(repo, "rev-parse", "HEAD")
        if code or head != row["git_commit"]:
            issues.append({**base, "issue": "commit_mismatch", "actual_commit": head, "expected_commit": row["git_commit"]})
            continue
        code, status = git(repo, "status", "--porcelain")
        if code:
            issues.append({**base, "issue": "status_unavailable"})
        elif status:
            issues.append({**base, "issue": "dirty", "changes": status.splitlines()})

    payload = {
        "manifest": args.manifest.relative_to(BASE_DIR).as_posix(),
        "rows": len(rows),
        "unique_sample_ids": not duplicates(rows, "sample_id"),
        "unique_repositories": not duplicates(rows, "repo"),
        "unique_commits": not duplicates(rows, "git_commit"),
        "manifest_clean_worktrees": sum(row["working_tree_clean"].lower() == "true" for row in rows),
        "currently_verifiable_clean_worktrees": len(rows) - len(issues),
        "issues": issues,
        "publication_gate": "pass" if not issues else "repair_or_disclose_snapshot_exceptions",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
