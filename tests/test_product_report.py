from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsecbench import analyze_repository, build_report  # noqa: E402


SOURCE = """\
from mcp.server.fastmcp import FastMCP
import subprocess
mcp = FastMCP("demo")

@mcp.tool()
def shell(command: str):
    if command:
        return subprocess.run(command, shell=True)
"""


def embedded_payload(page: str) -> dict:
    match = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', page, re.DOTALL)
    if not match:
        raise AssertionError("embedded report payload is missing")
    return json.loads(match.group(1))


class ProductReportTests(unittest.TestCase):
    def test_analyze_writes_self_contained_auditable_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            (repository / "agent.py").write_text(SOURCE, encoding="utf-8")
            result = analyze_repository(repository, base / "output")
            page_path = Path(result.summary.report_file)
            manifest_path = Path(result.summary.report_manifest_file)
            page = page_path.read_text(encoding="utf-8")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload = embedded_payload(page)

            self.assertEqual(manifest["candidate_count"], result.summary.candidate_count)
            self.assertEqual(manifest["renderer"], "agentsecbench_offline_report_v2")
            self.assertEqual(manifest["schema_version"], "1.1")
            self.assertFalse(manifest["policy_embedded"])
            self.assertTrue(manifest["validation_passed"])
            self.assertEqual(manifest["page_sha256"], hashlib.sha256(page_path.read_bytes()).hexdigest())
            self.assertEqual(len(payload["cases"]), result.summary.candidate_count)
            self.assertRegex(payload["reviewStorageKey"], r"^agentsecbench-review-v1-[0-9a-f]{16}$")
            self.assertIn("Security-ADG", page)
            self.assertIn("Analysis overview", page)
            self.assertIn("Evidence coverage", page)
            self.assertIn('id="confidence"', page)
            self.assertIn("Export review JSON", page)
            self.assertIn("Suppression draft", page)
            self.assertIn('id="reviewStatus"', page)
            self.assertIn("prefers-color-scheme:dark", page)
            self.assertIn("not a vulnerability report", page)
            self.assertNotRegex(page, r'<(?:script|link)[^>]+(?:src|href)=["\']https?://')
            command_case = next(case for case in payload["cases"] if case["category"] == "command_execution")
            self.assertRegex(command_case["fingerprint"], r"^ASBFP-[0-9A-F]{24}$")
            self.assertTrue(command_case["evidenceSnippets"])
            self.assertIn("MCP", {item["framework"] for item in command_case["frameworkEvidence"]})

    def test_report_escapes_script_terminators_in_evidence(self) -> None:
        graph = {
            "candidate_id": "C1", "graph_id": "G1", "claim_boundary": "candidate only",
            "provenance": {"file": "agent.py", "line_start": 1, "line_end": 1, "evidence_hash_verified": True},
            "nodes": [
                {"id": "n1", "type": "agent_or_program_symbol", "name": "agent"},
                {"id": "n2", "type": "security_sensitive_operation", "name": "eval", "category": "dynamic_code_execution", "confidence": "high", "evidence_lines": [1], "evidence_snippets": [{"line": 1, "text": "</script><script>alert(1)</script>"}]},
                {"id": "n3", "type": "external_effect", "target_class": "runtime_interpreter"},
                {"id": "n4", "type": "trust_boundary", "boundary": "input_to_code"},
            ],
            "edges": [], "analysis": {"engine": "test", "dependency_paths": [], "framework_evidence": [], "limitations": []},
            "views": {"sink_only": {"nodes": ["n2"], "edges": []}, "plain_adg": {"nodes": ["n1", "n2", "n3"], "edges": []}, "security_adg": {"nodes": ["n1", "n2", "n3", "n4"], "edges": [], "source_candidates": 0, "guard_candidates": 0, "dependency_paths": 0, "frameworks": []}},
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            build_report((graph,), {"graph_count": 1}, {"valid": True}, output)
            page = (output / "index.html").read_text(encoding="utf-8")
            self.assertEqual(page.count("</script>"), 2)
            self.assertEqual(embedded_payload(page)["cases"][0]["evidenceSnippets"][0]["text"], "</script><script>alert(1)</script>")

    def test_empty_report_is_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = build_report((), {"graph_count": 0}, {"valid": True}, Path(temporary))
            self.assertEqual(manifest["candidate_count"], 0)
            self.assertEqual(embedded_payload((Path(temporary) / "index.html").read_text(encoding="utf-8"))["cases"], [])


if __name__ == "__main__":
    unittest.main()
