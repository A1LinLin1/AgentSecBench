"""Create detached worktrees at manifest commits for reproducible baselines.

This never alters the original repository worktrees. It is intended for cases
where a repository has local reproduction or remediation edits but analysis
must use the frozen manifest commit.
"""

from __future__ import annotations

import argparse
import csv
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "frozen_baseline_worktrees"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={repo.as_posix()}", "-C", str(repo), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--split", choices=("development", "held_out_evaluation"))
    args = parser.parse_args()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if args.split:
        rows = [row for row in rows if row["experiment_split"] == args.split]
    args.output_root.mkdir(parents=True, exist_ok=True)
    for row in rows:
        original = (BASE_DIR / row["repository_path"]).resolve()
        destination = args.output_root / row["sample_id"]
        expected = row["git_commit"]
        if destination.exists():
            head = git(destination, "rev-parse", "HEAD")
            dirty = git(destination, "status", "--porcelain")
            if head != expected or dirty:
                raise RuntimeError(f"existing worktree is not a clean frozen snapshot: {destination}")
            print(f"[reuse] {row['sample_id']} {destination}")
            continue
        result = subprocess.run(
            ["git", "-c", f"safe.directory={original.as_posix()}", "-C", str(original), "worktree", "add", "--detach", str(destination), expected],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if result.returncode:
            raise RuntimeError(f"could not create {destination}: {result.stderr.strip()}")
        if git(destination, "rev-parse", "HEAD") != expected or git(destination, "status", "--porcelain"):
            raise RuntimeError(f"frozen snapshot validation failed: {destination}")
        print(f"[created] {row['sample_id']} {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
