"""SARIF 2.1.0 export for AgentSecBench static candidates."""

from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def build_sarif(findings: tuple[Finding, ...], tool_version: str) -> dict:
    categories = sorted({item.category for item in findings})
    evidence_by_category = {
        category: sorted({evidence for item in findings if item.category == category for evidence in item.evidence})
        for category in categories
    }
    rules = [
        {
            "id": f"agentsecbench/{category}",
            "name": category,
            "shortDescription": {"text": category.replace("_", " ").title()},
            "fullDescription": {"text": "; ".join(evidence_by_category[category]) or "Security-sensitive behavior candidate"},
            "defaultConfiguration": {"level": "warning"},
            "properties": {
                "precision": "high" if any(item.confidence == "high" for item in findings if item.category == category) else "medium",
                "tags": ["security", "llm-agent", "static-analysis", category],
            },
        }
        for category in categories
    ]
    results = []
    for finding in findings:
        message = f"{finding.category.replace('_', ' ')} candidate in {finding.symbol}"
        results.append({
            "ruleId": f"agentsecbench/{finding.category}",
            "level": "warning" if finding.confidence == "high" else "note",
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": finding.line_start, "endLine": finding.line_end},
                }
            }],
            "partialFingerprints": {
                "agentsecbenchFindingId/v1": finding.finding_id,
                "agentsecbenchStableFingerprint/v1": finding.fingerprint,
            },
            "properties": {
                "candidateId": finding.finding_id,
                "fingerprint": finding.fingerprint,
                "confidence": finding.confidence,
                "detectors": list(finding.detectors),
                "reviewStatus": finding.review_status,
                "claimBoundary": "static candidate; review required; not a vulnerability claim",
            },
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AgentSecBench", "version": tool_version,
                "informationUri": "https://github.com/A1LinLin1/AgentSecBench",
                "rules": rules,
            }},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}},
            "results": results,
            "properties": {
                "claimBoundary": "candidate discovery output; not vulnerability ground truth",
                "sourceExecutionUsed": False,
            },
        }],
    }


def write_sarif(path: Path, findings: tuple[Finding, ...], tool_version: str) -> dict:
    payload = build_sarif(findings, tool_version)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    temporary.replace(path)
    return payload
