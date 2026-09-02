"""Repair invalid or modified selected clones without deleting the originals.

Fresh clones are created and validated in a staging directory first. Only then
is the old directory moved into a timestamped quarantine directory and the
fresh clone moved into its canonical location.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import stat
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
SELECTION_FILE = BASE_DIR / "dataset" / "high_priority.csv"
METADATA_FILE = BASE_DIR / "metadata" / "repos.jsonl"
REPO_DIR = (BASE_DIR / "dataset" / "repos").resolve()
STAGING_DIR = (BASE_DIR / "dataset" / "_repair_staging").resolve()

WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def git_command(path: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={path.as_posix()}",
            "-C",
            str(path),
            *args,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def clone_is_clean(path: Path) -> tuple[bool, str]:
    if not path.is_dir():
        return False, "missing directory"
    revision = git_command(path, "rev-parse", "--verify", "HEAD")
    if revision.returncode != 0:
        return False, "invalid Git metadata"
    bare = git_command(path, "rev-parse", "--is-bare-repository")
    if bare.returncode == 0 and bare.stdout.strip().lower() == "true":
        fsck = git_command(path, "fsck", "--no-dangling", timeout=300)
        if fsck.returncode != 0:
            return False, "bare Git object store failed fsck"
        return True, "valid bare Git object store"
    status = git_command(path, "status", "--porcelain", timeout=120)
    if status.returncode != 0:
        return False, "git status failed"
    if status.stdout.strip():
        return False, f"modified working tree ({len(status.stdout.splitlines())} entries)"
    return True, "clean"


def ensure_within(path: Path, parent: Path) -> None:
    path.resolve().relative_to(parent.resolve())


def atomic_move_with_retry(source: Path, destination: Path) -> None:
    """Rename a directory on the same volume without copy/delete fallback."""
    last_error: OSError | None = None
    for delay in (0.5, 1, 2, 4, 8):
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            last_error = exc
            time.sleep(delay)
    assert last_error is not None
    raise last_error


def remove_tree(path: Path) -> None:
    def make_writable_and_retry(function, filename, _excinfo):
        os.chmod(filename, stat.S_IWRITE)
        function(filename)

    shutil.rmtree(path, onexc=make_writable_and_retry)


def is_windows_incompatible_path(path: str) -> bool:
    for component in path.replace("\\", "/").split("/"):
        if not component:
            continue
        if re.search(r'[<>:"\\|?*]', component):
            return True
        if component.endswith((" ", ".")):
            return True
        stem = component.split(".", 1)[0].upper()
        if stem in WINDOWS_RESERVED_NAMES:
            return True
    return False


def convert_staging_to_bare_object_store(path: Path) -> tuple[bool, str]:
    bare_path = path.with_name(path.name + ".bare-tmp")
    ensure_within(bare_path, STAGING_DIR)
    if bare_path.exists():
        remove_tree(bare_path)

    remote = git_command(path, "remote", "get-url", "origin")
    result = subprocess.run(
        ["git", "clone", "--bare", "--no-local", str(path), str(bare_path)],
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        check=False,
    )
    if result.returncode != 0:
        return False, f"local bare clone exited {result.returncode}"
    if remote.returncode == 0:
        set_remote = git_command(
            bare_path, "remote", "set-url", "origin", remote.stdout.strip()
        )
        if set_remote.returncode != 0:
            return False, "could not preserve origin URL in bare object store"

    valid, reason = clone_is_clean(bare_path)
    if not valid:
        return False, reason
    remove_tree(path)
    atomic_move_with_retry(bare_path, path)
    return True, "converted to bare Git object store"


def checkout_staged_clone(path: Path) -> tuple[bool, str]:
    listing = git_command(
        path, "ls-tree", "-r", "--name-only", "-z", "HEAD", timeout=120
    )
    if listing.returncode != 0:
        return False, "could not list Git tree"
    excluded = [
        item
        for item in listing.stdout.split("\0")
        if item and is_windows_incompatible_path(item)
    ]
    if excluded:
        print(
            "  Windows-incompatible paths require object-only storage: "
            + "; ".join(excluded),
            flush=True,
        )
        return convert_staging_to_bare_object_store(path)
    checkout = git_command(path, "checkout", "--force", "HEAD", timeout=600)
    if checkout.returncode != 0:
        return False, f"checkout failed: {checkout.stderr.strip()}"
    return True, "checked out"


def load_inputs() -> tuple[list[dict[str, str]], dict[str, dict]]:
    with SELECTION_FILE.open("r", encoding="utf-8-sig", newline="") as handle:
        selections = list(csv.DictReader(handle))
    metadata: dict[str, dict] = {}
    with METADATA_FILE.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                record = json.loads(line)
                metadata[record["repo"]] = record
    return selections, metadata


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--proxy",
        help=(
            "Proxy used only for fresh git clones, for example "
            "http://127.0.0.1:7993. Global Git configuration is not changed."
        ),
    )
    parser.add_argument(
        "--clone-attempts",
        type=int,
        default=3,
        help="Maximum clone attempts per repository (default: 3).",
    )
    parser.add_argument(
        "--repo",
        action="append",
        help="Repair only this owner/name repository; may be supplied more than once.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    selections, metadata = load_inputs()
    targets: list[tuple[str, Path, str]] = []
    requested_repos = set(args.repo or [])
    for row in selections:
        repo = row["repo"]
        if requested_repos and repo not in requested_repos:
            continue
        record = metadata.get(repo)
        if record is None:
            print(f"Missing metadata: {repo}", file=sys.stderr)
            return 1
        target = Path(record["local_path"]).resolve()
        ensure_within(target, REPO_DIR)
        valid, reason = clone_is_clean(target)
        if not valid:
            targets.append((repo, target, reason))

    known_repos = {row["repo"] for row in selections}
    unknown_repos = requested_repos - known_repos
    if unknown_repos:
        print(
            "Unknown selected repositories: " + ", ".join(sorted(unknown_repos)),
            file=sys.stderr,
        )
        return 1

    if not targets:
        print("All selected clones are valid and clean; no repair needed.")
        return 0

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    quarantine_dir = (BASE_DIR / "dataset" / f"_quarantine_{timestamp}").resolve()
    ensure_within(quarantine_dir, BASE_DIR / "dataset")
    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    repaired = 0
    for index, (repo, target, reason) in enumerate(targets, start=1):
        safe_name = repo.replace("/", "_")
        staging = (STAGING_DIR / safe_name).resolve()
        ensure_within(staging, STAGING_DIR)
        if staging.exists():
            staging_valid, _ = clone_is_clean(staging)
            if not staging_valid:
                recovered, recovery_reason = checkout_staged_clone(staging)
                if recovered:
                    staging_valid, _ = clone_is_clean(staging)
                if not staging_valid:
                    print(
                        f"  Existing staging clone unusable: {recovery_reason}",
                        flush=True,
                    )
                    remove_tree(staging)

        print(f"[{index}/{len(targets)}] Repairing {repo}: {reason}", flush=True)
        if not staging.exists():
            clone_command = ["git"]
            if args.proxy:
                clone_command.extend(
                    [
                        "-c",
                        f"http.proxy={args.proxy}",
                        "-c",
                        f"https.proxy={args.proxy}",
                    ]
                )
            clone_command.extend(
                [
                    "clone",
                    "--depth",
                    "1",
                    "--no-tags",
                    "--no-checkout",
                    f"https://github.com/{repo}.git",
                    str(staging),
                ]
            )
            clone_succeeded = False
            last_returncode = -1
            for attempt in range(1, max(1, args.clone_attempts) + 1):
                if attempt > 1:
                    print(
                        f"  Retry {attempt}/{args.clone_attempts} for {repo}",
                        flush=True,
                    )
                    time.sleep(min(2**attempt, 10))
                result = subprocess.run(
                    clone_command,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=600,
                    check=False,
                )
                last_returncode = result.returncode
                if result.returncode == 0:
                    checkout_ok, checkout_reason = checkout_staged_clone(staging)
                    if checkout_ok:
                        clone_succeeded = True
                        break
                    print(f"  {checkout_reason}", file=sys.stderr, flush=True)
                if staging.exists():
                    try:
                        remove_tree(staging)
                    except OSError as exc:
                        failures.append(
                            f"{repo}: failed clone could not be cleaned ({exc})"
                        )
                        break
            if not clone_succeeded:
                failures.append(f"{repo}: git clone exited {last_returncode}")
                continue

        staging_valid, staging_reason = clone_is_clean(staging)
        if not staging_valid:
            failures.append(f"{repo}: staged clone failed validation ({staging_reason})")
            continue

        quarantine_dir.mkdir(parents=True, exist_ok=True)
        backup = (quarantine_dir / safe_name).resolve()
        ensure_within(backup, quarantine_dir)
        if backup.exists():
            failures.append(f"{repo}: quarantine destination already exists")
            continue

        atomic_move_with_retry(target, backup)
        try:
            atomic_move_with_retry(staging, target)
        except Exception:
            if not target.exists() and backup.exists():
                atomic_move_with_retry(backup, target)
            raise

        final_valid, final_reason = clone_is_clean(target)
        if not final_valid:
            failed_fresh = quarantine_dir / f"{safe_name}.fresh-invalid"
            atomic_move_with_retry(target, failed_fresh)
            atomic_move_with_retry(backup, target)
            failures.append(f"{repo}: final validation failed ({final_reason})")
            continue
        repaired += 1

    print(f"Repaired: {repaired}/{len(targets)}")
    print(f"Quarantine: {quarantine_dir}")
    if failures:
        print("Failures:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
