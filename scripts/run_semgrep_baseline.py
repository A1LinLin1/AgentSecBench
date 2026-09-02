"""Run the frozen Semgrep sink baseline on verified pilot worktrees."""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
DEFAULT_CONFIG = BASE_DIR / "baselines" / "semgrep" / "predefined_sinks_v1.yml"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "baselines" / "development" / "semgrep"
DEFAULT_EXE = BASE_DIR / ".venv" / "Scripts" / "semgrep.exe"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={repo.as_posix()}", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.strip())
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--semgrep", type=Path, default=DEFAULT_EXE)
    parser.add_argument(
        "--split",
        default="development",
        choices=("development", "held_out_evaluation", "mutation_evaluation"),
        help="Manifest split to scan; mutation evaluation contains only derived, pinned worktrees.",
    )
    parser.add_argument("--snapshot-root", type=Path)
    parser.add_argument("--docker-image", help="run Semgrep in this pinned Docker image")
    parser.add_argument("--run-id", default="semgrep_predefined_sinks_v2")
    args = parser.parse_args()
    if args.snapshot_root:
        args.snapshot_root = args.snapshot_root.resolve()
    args.output_dir = args.output_dir.resolve()
    args.config = args.config.resolve()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = [row for row in csv.DictReader(handle) if row["experiment_split"] == args.split]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    runs = []
    for index, row in enumerate(rows, start=1):
        repo = ((args.snapshot_root / row["sample_id"]) if args.snapshot_root else (BASE_DIR / row["repository_path"])).resolve()
        head = git(repo, "rev-parse", "HEAD")
        dirty = git(repo, "status", "--porcelain")
        if head != row["git_commit"] or dirty:
            raise RuntimeError(f"frozen-worktree check failed for {row['repo']}")
        output = args.output_dir / f"{row['sample_id']}.json"
        if args.docker_image:
            command = [
                "docker", "run", "--rm", "--network", "none",
                "--volume", f"{repo}:/src:ro",
                "--volume", f"{args.config}:/config/rules.yml:ro",
                args.docker_image,
                "semgrep", "--metrics", "off", "--disable-version-check",
                "--config", "/config/rules.yml", "--json", "--jobs", "1", "/src",
            ]
        else:
            command = [
                str(args.semgrep),
                "--metrics", "off", "--disable-version-check", "--config", str(args.config),
                "--json", "--output", str(output), "--jobs", "1", str(repo),
            ]
        print(f"[{index}/{len(rows)}] {row['repo']}", flush=True)
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.returncode not in (0, 1):
            raise RuntimeError(f"Semgrep failed for {row['repo']}: {result.stderr[-4000:]}")
        if args.docker_image:
            output.write_text(result.stdout, encoding="utf-8")
        payload = json.loads(output.read_text(encoding="utf-8"))
        runs.append(
            {
                "sample_id": row["sample_id"],
                "repo": row["repo"],
                "commit": head,
                "findings": len(payload.get("results", [])),
                "errors": len(payload.get("errors", [])),
                "output": output.relative_to(BASE_DIR).as_posix(),
                "source_root": repo.relative_to(BASE_DIR).as_posix(),
            }
        )
    summary = {
        "run_id": args.run_id,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "split": args.split,
        "rules": args.config.relative_to(BASE_DIR).as_posix(),
        "label_inputs_used": False,
        "held_out_used": args.split == "held_out_evaluation",
        "held_out_labels_used": False,
        "snapshot_root": args.snapshot_root.relative_to(BASE_DIR).as_posix() if args.snapshot_root else None,
        "execution_engine": "docker" if args.docker_image else "local_executable",
        "docker_image": args.docker_image,
        "docker_network_disabled": bool(args.docker_image),
        "runs": runs,
        "total_findings": sum(row["findings"] for row in runs),
        "total_errors": sum(row["errors"] for row in runs),
    }
    summary_path = args.output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
