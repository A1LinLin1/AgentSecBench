"""Validate static findings against the exact frozen Git commit contents."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from static_scan import BASE_DIR, iter_commit_files


DEFAULT_MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
DEFAULT_FINDINGS = BASE_DIR / "analysis" / "raw_findings.jsonl"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--findings", type=Path, default=DEFAULT_FINDINGS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest = list(csv.DictReader(handle))
    with args.findings.open("r", encoding="utf-8") as handle:
        findings = [json.loads(line) for line in handle if line.strip()]

    errors: list[str] = []
    ids = [item["annotation_id"] for item in findings]
    if len(ids) != len(set(ids)):
        errors.append("duplicate annotation IDs")

    manifest_by_repo = {row["repo"]: row for row in manifest}
    findings_by_repo: dict[str, list[dict]] = {}
    for item in findings:
        findings_by_repo.setdefault(item["repo"], []).append(item)
        manifest_row = manifest_by_repo.get(item["repo"])
        if manifest_row is None:
            errors.append(f"{item['annotation_id']}: repository is outside manifest")
        elif item["git_commit"] != manifest_row["git_commit"]:
            errors.append(f"{item['annotation_id']}: commit differs from manifest")

    for row in manifest:
        repo_findings = findings_by_repo.get(row["repo"], [])
        expected: dict[tuple[str, int], str] = {}
        for item in repo_findings:
            lines = item.get("evidence_lines", [])
            hashes = item.get("evidence_line_sha256", [])
            if len(lines) != len(hashes):
                errors.append(f"{item['annotation_id']}: evidence/hash length mismatch")
                continue
            if lines != sorted(set(lines)):
                errors.append(f"{item['annotation_id']}: evidence lines are not unique/sorted")
            for line_number, digest in zip(lines, hashes):
                expected[(item["file"], int(line_number))] = digest

        seen: set[tuple[str, int]] = set()
        repo_path = (BASE_DIR / row["repository_path"]).resolve()
        for relative_path, text in iter_commit_files(repo_path, row["git_commit"]):
            relevant = {
                line_number: digest
                for (path, line_number), digest in expected.items()
                if path == relative_path
            }
            if not relevant:
                continue
            source_lines = text.splitlines()
            for line_number, digest in relevant.items():
                if line_number < 1 or line_number > len(source_lines):
                    errors.append(f"{row['repo']}:{relative_path}:{line_number}: line missing")
                    continue
                actual = hashlib.sha256(
                    source_lines[line_number - 1].strip().encode("utf-8", errors="replace")
                ).hexdigest()
                if actual != digest:
                    errors.append(f"{row['repo']}:{relative_path}:{line_number}: hash mismatch")
                seen.add((relative_path, line_number))
        for location in sorted(set(expected) - seen):
            errors.append(f"{row['repo']}:{location[0]}:{location[1]}: file not found")

    if errors:
        print(f"Validation failed with {len(errors)} error(s):")
        for error in errors[:100]:
            print(f"  - {error}")
        return 1

    print(f"Validation passed: {len(findings)} findings")
    print("By category:")
    for category, count in Counter(item["category"] for item in findings).most_common():
        print(f"  {category}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
