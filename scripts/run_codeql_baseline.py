"""Create and analyze CodeQL databases for frozen development repositories."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
DEFAULT_CODEQL = BASE_DIR / "tools" / "codeql-v2.26.2" / "codeql" / "codeql.exe"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "baselines" / "development" / "codeql"
LANGUAGES = {
    "python": {
        "markers": ("Python:",),
        "suite": "codeql/python-queries:codeql-suites/python-security-and-quality.qls",
    },
    "javascript": {
        "markers": ("JavaScript:", "TypeScript:"),
        "suite": "codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls",
    },
}


def run(command: list[str], log: Path) -> None:
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_text(result.stdout + "\n--- STDERR ---\n" + result.stderr, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}); see {log}")


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={repo.as_posix()}", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def has_language(counts: str, markers: tuple[str, ...]) -> bool:
    for item in counts.split(";"):
        if any(item.startswith(marker) for marker in markers):
            try:
                return int(item.rsplit(":", 1)[1]) > 0
            except ValueError:
                return False
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--codeql", type=Path, default=DEFAULT_CODEQL)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--language", action="append", choices=tuple(LANGUAGES))
    parser.add_argument(
        "--split",
        choices=("development", "held_out_evaluation", "mutation_evaluation"),
        default="development",
        help="Manifest split to analyze; mutation evaluation uses derived pinned worktrees.",
    )
    parser.add_argument("--build-mode", choices=("none",), default="none")
    parser.add_argument("--python-executable-name", choices=("py", "python", "python3"), default="python")
    parser.add_argument("--run-id", default="codeql_security_and_quality_v2_buildmode_none_pythonexec")
    parser.add_argument("--snapshot-root", type=Path)
    parser.add_argument("--resume", action="store_true", help="reuse only runs having both a database and SARIF output")
    args = parser.parse_args()
    args.output_dir = args.output_dir.resolve()
    if args.snapshot_root:
        args.snapshot_root = args.snapshot_root.resolve()
    selected_languages = set(args.language or LANGUAGES)
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [row for row in csv.DictReader(handle) if row["experiment_split"] == args.split]
    databases = args.output_dir / "databases"
    sarif_dir = args.output_dir / "sarif"
    logs = args.output_dir / "logs"
    for directory in (databases, sarif_dir, logs):
        directory.mkdir(parents=True, exist_ok=True)
    runs = []
    work = [
        (row, language, settings)
        for row in rows
        for language, settings in LANGUAGES.items()
        if language in selected_languages and has_language(row["language_file_counts"], settings["markers"])
    ]
    for index, (row, language, settings) in enumerate(work, start=1):
        repo = ((args.snapshot_root / row["sample_id"]) if args.snapshot_root else (BASE_DIR / row["repository_path"])).resolve()
        head = git(repo, "rev-parse", "HEAD")
        if head != row["git_commit"] or git(repo, "status", "--porcelain"):
            raise RuntimeError(f"frozen-worktree check failed for {row['repo']}")
        stem = f"{row['sample_id']}_{language}"
        database = databases / stem
        sarif = sarif_dir / f"{stem}.sarif"
        if args.resume and database.exists() and sarif.exists():
            payload = json.loads(sarif.read_text(encoding="utf-8"))
            results = [result for sarif_run in payload.get("runs", []) for result in sarif_run.get("results", [])]
            runs.append(
                {
                    "sample_id": row["sample_id"], "repo": row["repo"], "commit": head,
                    "language": language, "suite": settings["suite"], "sarif_results": len(results),
                    "database": database.relative_to(BASE_DIR).as_posix(), "sarif": sarif.relative_to(BASE_DIR).as_posix(),
                    "source_root": repo.relative_to(BASE_DIR).as_posix(), "reused": True,
                }
            )
            print(f"[{index}/{len(work)}] reuse {row['repo']} ({language})", flush=True)
            continue
        if database.exists() or sarif.exists():
            raise RuntimeError(f"refusing to overwrite existing baseline artifact: {stem}")
        print(f"[{index}/{len(work)}] create {row['repo']} ({language})", flush=True)
        create_command = [
            str(args.codeql), "database", "create", str(database), f"--language={language}",
            f"--source-root={repo}", f"--build-mode={args.build_mode}",
        ]
        if language == "python":
            create_command.append(f"--extractor-option=python.python_executable_name={args.python_executable_name}")
        run(create_command, logs / f"{stem}_create.log")
        print(f"[{index}/{len(work)}] analyze {row['repo']} ({language})", flush=True)
        run(
            [
                str(args.codeql), "database", "analyze", str(database), settings["suite"],
                "--format=sarif-latest", f"--output={sarif}", "--threads=0",
            ],
            logs / f"{stem}_analyze.log",
        )
        payload = json.loads(sarif.read_text(encoding="utf-8"))
        results = [result for sarif_run in payload.get("runs", []) for result in sarif_run.get("results", [])]
        runs.append(
            {
                "sample_id": row["sample_id"],
                "repo": row["repo"],
                "commit": head,
                "language": language,
                "suite": settings["suite"],
                "sarif_results": len(results),
                "database": database.relative_to(BASE_DIR).as_posix(),
                "sarif": sarif.relative_to(BASE_DIR).as_posix(),
                "source_root": repo.relative_to(BASE_DIR).as_posix(),
                "reused": False,
            }
        )
    summary = {
        "run_id": args.run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "split": args.split,
        "label_inputs_used": False,
        "held_out_used": args.split == "held_out_evaluation",
        "held_out_labels_used": False,
        "build_mode": args.build_mode,
        "python_executable_name": args.python_executable_name,
        "snapshot_root": args.snapshot_root.relative_to(BASE_DIR).as_posix() if args.snapshot_root else None,
        "runs": runs,
        "total_sarif_results": sum(row["sarif_results"] for row in runs),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
