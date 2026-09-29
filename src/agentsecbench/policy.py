"""Auditable baseline and suppression policy for team adoption."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable

from ._version import VERSION
from .models import Finding


class PolicyError(ValueError):
    """Raised when policy input cannot be applied safely."""


@dataclass(frozen=True)
class Suppression:
    suppression_id: str
    fingerprint: str
    reason: str
    owner: str
    expires: date | None


def _atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def read_findings_jsonl(path: Path) -> tuple[dict, ...]:
    try:
        records = tuple(
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"cannot read findings file {path}: {error}") from error
    missing = [index for index, item in enumerate(records, 1) if not item.get("fingerprint")]
    if missing:
        raise PolicyError(
            f"findings file lacks stable fingerprints on {len(missing)} record(s); rerun analysis with the current version"
        )
    return records


def write_baseline(findings_file: Path, output: Path) -> dict:
    records = read_findings_jsonl(findings_file)
    fingerprints = sorted({str(item["fingerprint"]) for item in records})
    payload = {
        "schema_version": "1.0",
        "kind": "agentsecbench_baseline",
        "agentsecbench_version": VERSION,
        "finding_count": len(records),
        "unique_fingerprint_count": len(fingerprints),
        "fingerprints": fingerprints,
        "claim_boundary": "accepted historical static candidates; not vulnerability adjudications",
    }
    _atomic_json(output, payload)
    return payload


def load_baseline(path: Path) -> set[str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"cannot read baseline {path}: {error}") from error
    if payload.get("schema_version") != "1.0" or payload.get("kind") != "agentsecbench_baseline":
        raise PolicyError(f"unsupported baseline schema: {path}")
    fingerprints = payload.get("fingerprints")
    if not isinstance(fingerprints, list) or not all(isinstance(item, str) and item for item in fingerprints):
        raise PolicyError(f"baseline fingerprints must be non-empty strings: {path}")
    if len(fingerprints) != len(set(fingerprints)):
        raise PolicyError(f"baseline contains duplicate fingerprints: {path}")
    return set(fingerprints)


def load_suppressions(path: Path) -> tuple[Suppression, ...]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise PolicyError(f"cannot read suppressions {path}: {error}") from error
    unknown = sorted(set(payload) - {"schema_version", "suppressions"})
    if unknown:
        raise PolicyError(f"unknown suppression keys: {', '.join(unknown)}")
    if payload.get("schema_version") != "1.0":
        raise PolicyError("suppression schema_version must be '1.0'")
    items = payload.get("suppressions", [])
    if not isinstance(items, list):
        raise PolicyError("suppressions must use [[suppressions]] tables")
    result = []
    for index, item in enumerate(items, 1):
        if not isinstance(item, dict):
            raise PolicyError(f"suppressions[{index}] must be a table")
        unknown_item = sorted(set(item) - {"id", "fingerprint", "reason", "owner", "expires"})
        if unknown_item:
            raise PolicyError(f"unknown keys in suppressions[{index}]: {', '.join(unknown_item)}")
        required = ("id", "fingerprint", "reason", "owner")
        if any(not isinstance(item.get(key), str) or not item[key].strip() for key in required):
            raise PolicyError(f"suppressions[{index}] requires non-empty id, fingerprint, reason, and owner")
        raw_expiry = item.get("expires")
        expiry = None
        if raw_expiry is not None:
            if isinstance(raw_expiry, date):
                expiry = raw_expiry
            elif isinstance(raw_expiry, str):
                try:
                    expiry = date.fromisoformat(raw_expiry)
                except ValueError as error:
                    raise PolicyError(f"suppressions[{index}].expires must be YYYY-MM-DD") from error
            else:
                raise PolicyError(f"suppressions[{index}].expires must be YYYY-MM-DD")
        result.append(Suppression(item["id"], item["fingerprint"], item["reason"], item["owner"], expiry))
    identifiers = [item.suppression_id for item in result]
    fingerprints = [item.fingerprint for item in result]
    if len(identifiers) != len(set(identifiers)):
        raise PolicyError("suppression ids must be unique")
    if len(fingerprints) != len(set(fingerprints)):
        raise PolicyError("suppression fingerprints must be unique")
    return tuple(result)


def evaluate_policy(
    findings: Iterable[Finding],
    *,
    baseline_path: Path | None = None,
    suppressions_path: Path | None = None,
    blocking_categories: tuple[str, ...] = (),
    minimum_confidence: str = "medium",
    today: date | None = None,
) -> dict:
    if minimum_confidence not in {"medium", "high"}:
        raise PolicyError("minimum_confidence must be 'medium' or 'high'")
    baseline = load_baseline(baseline_path) if baseline_path else set()
    suppressions = load_suppressions(suppressions_path) if suppressions_path else ()
    evaluation_date = today or date.today()
    active = {
        item.fingerprint: item
        for item in suppressions
        if item.expires is None or item.expires >= evaluation_date
    }
    expired = [item for item in suppressions if item.expires is not None and item.expires < evaluation_date]
    records = []
    confidence_rank = {"medium": 1, "high": 2}
    minimum_rank = confidence_rank[minimum_confidence]
    category_filter = set(blocking_categories)
    for finding in findings:
        suppression = active.get(finding.fingerprint)
        baseline_status = "existing" if finding.fingerprint in baseline else "new"
        policy_match = (
            (not category_filter or finding.category in category_filter)
            and confidence_rank.get(finding.confidence, 0) >= minimum_rank
        )
        blocking = baseline_status == "new" and suppression is None and policy_match
        records.append({
            "finding_id": finding.finding_id,
            "fingerprint": finding.fingerprint,
            "path": finding.path,
            "line": finding.line_start,
            "category": finding.category,
            "confidence": finding.confidence,
            "baseline_status": baseline_status,
            "suppressed": suppression is not None,
            "suppression_id": suppression.suppression_id if suppression else None,
            "policy_match": policy_match,
            "blocking": blocking,
        })
    new_unsuppressed = [item for item in records if item["baseline_status"] == "new" and not item["suppressed"]]
    blocking = [item for item in records if item["blocking"]]
    blocking_counts: dict[str, int] = {}
    for item in blocking:
        blocking_counts[item["category"]] = blocking_counts.get(item["category"], 0) + 1
    return {
        "schema_version": "1.0",
        "status": "completed",
        "baseline_file": str(baseline_path) if baseline_path else None,
        "suppressions_file": str(suppressions_path) if suppressions_path else None,
        "baseline_configured": baseline_path is not None,
        "total_findings": len(records),
        "existing_findings": sum(item["baseline_status"] == "existing" for item in records),
        "new_findings": sum(item["baseline_status"] == "new" for item in records),
        "suppressed_findings": sum(item["suppressed"] for item in records),
        "new_unsuppressed_findings": len(new_unsuppressed),
        "blocking_findings": len(blocking),
        "blocking_category_counts": dict(sorted(blocking_counts.items())),
        "policy_filters": {
            "blocking_categories": sorted(category_filter),
            "minimum_confidence": minimum_confidence,
        },
        "expired_suppressions": [
            {"id": item.suppression_id, "fingerprint": item.fingerprint, "expires": item.expires.isoformat()}
            for item in expired
        ],
        "findings": records,
        "claim_boundary": "workflow classification of static candidates; not vulnerability adjudication",
    }


def write_policy_report(path: Path, report: dict) -> None:
    _atomic_json(path, report)


def policy_markdown(report: dict, *, limit: int = 50) -> str:
    """Render a concise, untrusted-text-safe CI job summary."""

    def cell(value: object) -> str:
        return str(value).replace("\\", "/").replace("|", "\\|").replace("\r", " ").replace("\n", " ")

    status = "PASS" if report["blocking_findings"] == 0 else "FAIL"
    rows = [
        "# AgentSecBench policy summary",
        "",
        f"**{status}** — {report['blocking_findings']} blocking new candidate(s).",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Total candidates | {report['total_findings']} |",
        f"| Existing baseline candidates | {report['existing_findings']} |",
        f"| New candidates | {report['new_findings']} |",
        f"| Suppressed candidates | {report['suppressed_findings']} |",
        f"| New unsuppressed candidates | {report['new_unsuppressed_findings']} |",
        f"| **Blocking candidates** | **{report['blocking_findings']}** |",
        "",
        f"Minimum blocking confidence: `{cell(report['policy_filters']['minimum_confidence'])}`",
        "",
        "Blocking categories: " + (
            ", ".join(f"`{cell(item)}`" for item in report["policy_filters"]["blocking_categories"])
            or "all categories"
        ),
        "",
    ]
    blocking = [item for item in report["findings"] if item["blocking"]]
    if blocking:
        rows.extend([
            "## Blocking candidates",
            "",
            "| Candidate | Category | Confidence | Location |",
            "|---|---|---|---|",
        ])
        rows.extend(
            f"| `{cell(item['finding_id'])}` | `{cell(item['category'])}` | {cell(item['confidence'])} | `{cell(item['path'])}:{item['line']}` |"
            for item in blocking[:limit]
        )
        if len(blocking) > limit:
            rows.extend(["", f"{len(blocking) - limit} additional blocking candidate(s) omitted; inspect `policy.json`."])
        rows.append("")
    if report["expired_suppressions"]:
        rows.extend([
            "## Expired suppressions",
            "",
            "| ID | Fingerprint | Expired |",
            "|---|---|---|",
        ])
        rows.extend(
            f"| `{cell(item['id'])}` | `{cell(item['fingerprint'])}` | {cell(item['expires'])} |"
            for item in report["expired_suppressions"]
        )
        rows.append("")
    rows.extend([
        "> Static-analysis workflow classification; not vulnerability adjudication.",
        "",
    ])
    return "\n".join(rows)


def write_policy_markdown(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(policy_markdown(report), encoding="utf-8", newline="\n")
    temporary.replace(path)
