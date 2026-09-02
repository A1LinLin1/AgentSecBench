"""Freeze the selected AgentSecBench corpus into a reproducible manifest.

This script is intentionally read-only with respect to cloned repositories. It
does not import, build, install, or execute any code from the corpus.
"""

from __future__ import annotations

import argparse
import configparser
import csv
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SELECTION = BASE_DIR / "dataset" / "high_priority.csv"
DEFAULT_METADATA = BASE_DIR / "metadata" / "repos.jsonl"
DEFAULT_OUTPUT = BASE_DIR / "dataset" / "corpus_manifest.csv"

SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
}

LANGUAGE_BY_EXTENSION = {
    ".c": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cs": "C#",
    ".go": "Go",
    ".java": "Java",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".mjs": "JavaScript",
    ".php": "PHP",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".scala": "Scala",
    ".sh": "Shell",
    ".swift": "Swift",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
}

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
LICENSE_NAMES = {
    "copying",
    "copying.md",
    "copying.txt",
    "license",
    "license.md",
    "license.txt",
}

FIELDNAMES = [
    "sample_id",
    "repo",
    "url",
    "ecosystem",
    "stars_at_selection",
    "selection_score",
    "selection_priority",
    "analysis_required",
    "selection_method",
    "repository_path",
    "git_commit",
    "commit_date_utc",
    "default_branch",
    "remote_url",
    "is_shallow_clone",
    "snapshot_mode",
    "sparse_checkout",
    "sparse_excluded_paths",
    "working_tree_clean",
    "file_count",
    "source_file_count",
    "source_bytes",
    "dominant_language",
    "language_file_counts",
    "license_files",
    "frozen_at_utc",
]


class FreezeError(RuntimeError):
    """Raised when a selected repository cannot be frozen reliably."""


def run_git(repo_path: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={repo_path.as_posix()}",
            "-C",
            str(repo_path),
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise FreezeError(f"git {' '.join(args)} failed: {message}")
    return result.stdout.strip()


def read_jsonl(path: Path) -> dict[str, dict]:
    records: dict[str, dict] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            repo = record.get("repo")
            if not repo:
                raise FreezeError(f"{path}:{line_number} has no repo field")
            if repo in records:
                raise FreezeError(f"duplicate metadata entry for {repo}")
            records[repo] = record
    return records


def iter_corpus_files(repo_path: Path):
    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(repo_path)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        yield path, relative


def inventory(repo_path: Path) -> dict[str, str | int]:
    file_count = 0
    source_file_count = 0
    source_bytes = 0
    languages: Counter[str] = Counter()
    license_files: list[str] = []

    for path, relative in iter_corpus_files(repo_path):
        file_count += 1
        suffix = path.suffix.lower()
        if suffix in SOURCE_EXTENSIONS:
            source_file_count += 1
            try:
                source_bytes += path.stat().st_size
            except OSError:
                pass
            languages[LANGUAGE_BY_EXTENSION[suffix]] += 1

        if path.name.lower() in LICENSE_NAMES:
            license_files.append(relative.as_posix())

    dominant_language = ""
    if languages:
        dominant_language = languages.most_common(1)[0][0]

    language_counts = ";".join(
        f"{language}:{count}" for language, count in languages.most_common()
    )

    return {
        "file_count": file_count,
        "source_file_count": source_file_count,
        "source_bytes": source_bytes,
        "dominant_language": dominant_language,
        "language_file_counts": language_counts,
        "license_files": ";".join(sorted(license_files)),
    }


def git_tree_inventory(repo_path: Path) -> dict[str, str | int]:
    output = run_git(repo_path, "ls-tree", "-r", "-l", "-z", "HEAD")
    file_count = 0
    source_file_count = 0
    source_bytes = 0
    languages: Counter[str] = Counter()
    license_files: list[str] = []

    for record in output.split("\0"):
        if not record or "\t" not in record:
            continue
        metadata, relative = record.split("\t", 1)
        parts = metadata.split()
        if len(parts) < 4 or parts[1] != "blob":
            continue
        file_count += 1
        suffix = Path(relative).suffix.lower()
        try:
            size = int(parts[3])
        except ValueError:
            size = 0
        if suffix in SOURCE_EXTENSIONS:
            source_file_count += 1
            source_bytes += size
            languages[LANGUAGE_BY_EXTENSION[suffix]] += 1
        if Path(relative).name.lower() in LICENSE_NAMES:
            license_files.append(relative)

    dominant_language = languages.most_common(1)[0][0] if languages else ""
    language_counts = ";".join(
        f"{language}:{count}" for language, count in languages.most_common()
    )
    return {
        "file_count": file_count,
        "source_file_count": source_file_count,
        "source_bytes": source_bytes,
        "dominant_language": dominant_language,
        "language_file_counts": language_counts,
        "license_files": ";".join(sorted(license_files)),
    }


def normalize_remote(remote_url: str) -> str:
    if remote_url.endswith(".git"):
        return remote_url[:-4]
    return remote_url


def git_layout(repo_path: Path) -> tuple[Path, bool]:
    worktree_git = repo_path / ".git"
    if worktree_git.is_dir():
        return worktree_git, False
    if (repo_path / "HEAD").is_file() and (repo_path / "objects").is_dir():
        return repo_path, True
    raise FreezeError(f"not a Git repository or bare object store: {repo_path}")


def read_local_git_config(git_dir: Path) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(interpolation=None)
    parser.read(git_dir / "config", encoding="utf-8")
    return parser


def head_branch(git_dir: Path) -> str:
    value = (git_dir / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
    prefix = "ref: refs/heads/"
    return value[len(prefix) :] if value.startswith(prefix) else "HEAD"


def sparse_checkout_info(repo_path: Path) -> tuple[str, str]:
    git_dir, is_bare = git_layout(repo_path)
    if is_bare:
        return "false", ""
    config = read_local_git_config(git_dir)
    enabled = config.getboolean("core", "sparseCheckout", fallback=False)
    if not enabled:
        return "false", ""

    sparse_file = git_dir / "info" / "sparse-checkout"
    exclusions: list[str] = []
    if sparse_file.is_file():
        for line in sparse_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("!"):
                exclusions.append(line[1:].lstrip("/"))
    return "true", ";".join(exclusions)


def freeze_repository(
    sample_id: str,
    selection: dict[str, str],
    metadata: dict,
    frozen_at: str,
) -> dict[str, str | int]:
    repo_name = selection["repo"]
    repo_path = Path(metadata["local_path"]).resolve()
    if not repo_path.is_dir():
        raise FreezeError(f"repository directory is missing: {repo_path}")
    git_dir, is_bare = git_layout(repo_path)
    git_config = read_local_git_config(git_dir)
    revision_data = run_git(repo_path, "show", "-s", "--format=%H%x1f%ct", "HEAD")
    commit, commit_timestamp = revision_data.split("\x1f", 1)
    commit_date = datetime.fromtimestamp(
        int(commit_timestamp), timezone.utc
    ).isoformat()
    branch = head_branch(git_dir)
    remote = git_config.get('remote "origin"', "url", fallback=f"https://github.com/{repo_name}")
    shallow = str((git_dir / "shallow").is_file()).lower()
    if is_bare:
        clean = "not_applicable"
        sparse_enabled, sparse_exclusions = "false", ""
        snapshot_mode = "bare_git_object_store"
    else:
        status = run_git(
            repo_path,
            "status",
            "--porcelain",
            "--untracked-files=no",
        )
        clean = str(not bool(status)).lower()
        sparse_enabled, sparse_exclusions = sparse_checkout_info(repo_path)
        snapshot_mode = "working_tree"
    files = git_tree_inventory(repo_path)

    return {
        "sample_id": sample_id,
        "repo": repo_name,
        "url": f"https://github.com/{repo_name}",
        "ecosystem": selection.get("ecosystem", ""),
        "stars_at_selection": selection.get("stars", ""),
        "selection_score": selection.get("score", ""),
        "selection_priority": selection.get("priority", ""),
        "analysis_required": selection.get("analysis_required", ""),
        "selection_method": "risk_directed_high_priority",
        "repository_path": repo_path.relative_to(BASE_DIR).as_posix(),
        "git_commit": commit,
        "commit_date_utc": commit_date,
        "default_branch": branch,
        "remote_url": normalize_remote(remote),
        "is_shallow_clone": shallow.lower(),
        "snapshot_mode": snapshot_mode,
        "sparse_checkout": sparse_enabled,
        "sparse_excluded_paths": sparse_exclusions,
        "working_tree_clean": clean,
        **files,
        "frozen_at_utc": frozen_at,
    }


def validate_manifest(rows: list[dict], expected_repos: list[str]) -> list[str]:
    errors: list[str] = []
    repos = [str(row["repo"]) for row in rows]
    sample_ids = [str(row["sample_id"]) for row in rows]

    if repos != expected_repos:
        errors.append("manifest repository order/content differs from selection file")
    if len(repos) != len(set(repos)):
        errors.append("manifest contains duplicate repositories")
    if len(sample_ids) != len(set(sample_ids)):
        errors.append("manifest contains duplicate sample IDs")

    for row in rows:
        repo = row["repo"]
        commit = str(row["git_commit"])
        if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit.lower()):
            errors.append(f"{repo}: invalid Git commit SHA")
        if row["working_tree_clean"] not in {"true", "not_applicable"}:
            errors.append(f"{repo}: working tree is not clean")
        if int(row["file_count"]) <= 0:
            errors.append(f"{repo}: repository inventory is empty")

    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", type=Path, default=DEFAULT_SELECTION)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--allow-incomplete",
        action="store_true",
        help="write valid rows even if one or more selected repositories fail",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    metadata_by_repo = read_jsonl(args.metadata)
    frozen_at = datetime.now(timezone.utc).isoformat()

    with args.selection.open("r", encoding="utf-8-sig", newline="") as handle:
        selections = list(csv.DictReader(handle))

    rows: list[dict] = []
    failures: list[str] = []
    for index, selection in enumerate(selections, start=1):
        repo = selection["repo"]
        print(f"[{index}/{len(selections)}] Freezing {repo}", flush=True)
        metadata = metadata_by_repo.get(repo)
        if metadata is None:
            failures.append(f"{repo}: missing from metadata")
            continue
        try:
            rows.append(
                freeze_repository(
                    f"ASB{index:04d}",
                    selection,
                    metadata,
                    frozen_at,
                )
            )
        except (FreezeError, OSError, subprocess.TimeoutExpired) as exc:
            failures.append(f"{repo}: {exc}")

    validation_errors = validate_manifest(
        rows, [selection["repo"] for selection in selections]
    )
    failures.extend(validation_errors)

    if failures and not args.allow_incomplete:
        print("Corpus freeze failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(args.output)

    print(f"Frozen repositories: {len(rows)}/{len(selections)}")
    print(f"Manifest: {args.output}")
    if failures:
        print(f"Warnings: {len(failures)}", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
