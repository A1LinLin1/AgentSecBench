from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SCRIPTS = ROOT / "scripts"
for directory in (SRC, SCRIPTS):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from agentsecbench import ScanOptions, analyze_repository  # noqa: E402
from agentsecbench.cli import main  # noqa: E402
from agentsecbench.scanner.rules import RULES, rule_signature  # noqa: E402
from static_scan import RULES as LEGACY_RULES  # noqa: E402


PYTHON_SOURCE = """\
import subprocess

@mcp.tool()
def run_command(command):
    subprocess.run(command)

def evaluate(code):
    return eval(code)

# exec("comment-only")
TEXT = "compile('string-only')"
"""

TYPESCRIPT_SOURCE = """\
export async function fetchPage(url: string) {
  return fetch(url);
}
"""


class ProductScannerTests(unittest.TestCase):
    def make_repository(self, root: Path) -> None:
        (root / "src").mkdir()
        (root / "src" / "agent.py").write_text(PYTHON_SOURCE, encoding="utf-8")
        (root / "src" / "client.ts").write_text(TYPESCRIPT_SOURCE, encoding="utf-8")
        (root / "src" / "binary.py").write_bytes(b"before\0after")
        (root / "node_modules").mkdir()
        (root / "node_modules" / "ignored.js").write_text("eval(userInput);\n", encoding="utf-8")

    def test_product_rules_match_frozen_research_rules(self) -> None:
        product = [rule_signature(item) for item in RULES]
        legacy = [
            (
                item.category,
                item.detector,
                item.pattern.pattern,
                item.pattern.flags,
                item.confidence,
                item.evidence,
            )
            for item in LEGACY_RULES
        ]
        self.assertEqual(product, legacy)

    def test_analyze_repository_is_safe_deterministic_and_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            self.make_repository(repository)
            first = analyze_repository(repository, base / "first")
            second = analyze_repository(repository, base / "second")

            first_payload = [item.to_dict() for item in first.findings]
            second_payload = [item.to_dict() for item in second.findings]
            self.assertEqual(first_payload, second_payload)
            self.assertEqual(first.summary.files_scanned, 2)
            self.assertEqual(first.summary.files_skipped_binary, 1)
            self.assertGreaterEqual(first.summary.directories_pruned, 1)
            self.assertEqual(
                {item.category for item in first.findings},
                {"command_execution", "dynamic_code_execution", "external_tool_invocation", "network_access"},
            )
            self.assertFalse(any("node_modules" in item.path for item in first.findings))
            self.assertEqual(len({item.finding_id for item in first.findings}), len(first.findings))
            self.assertEqual(len({item.fingerprint for item in first.findings}), len(first.findings))
            self.assertTrue((base / "first" / "findings.jsonl").is_file())
            self.assertTrue((base / "first" / "security-adg.jsonl").is_file())
            self.assertTrue((base / "first" / "security-adg-summary.json").is_file())
            self.assertTrue((base / "first" / "validation.json").is_file())
            self.assertTrue((base / "first" / "report" / "index.html").is_file())
            self.assertTrue((base / "first" / "report" / "manifest.json").is_file())
            self.assertEqual(first.summary.graph_count, len(first.findings))
            self.assertTrue(first.validation["valid"])
            summary = json.loads((base / "first" / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["candidate_count"], len(first.findings))
            self.assertEqual(summary["graph_count"], len(first.findings))
            self.assertIn("not vulnerability claims", summary["claim_boundary"])

    def test_include_and_exclude_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            self.make_repository(repository)
            result = analyze_repository(
                repository,
                base / "output",
                options=ScanOptions(include=("*.py",), exclude=("*binary.py",)),
            )
            self.assertTrue(result.findings)
            self.assertTrue(all(item.path.endswith(".py") for item in result.findings))
            self.assertEqual(result.summary.files_scanned, 1)

    def test_cli_analyze_json_and_fail_on_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            self.make_repository(repository)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main(
                    [
                        "analyze",
                        str(repository),
                        "--output",
                        str(base / "output"),
                        "--json",
                        "--fail-on-findings",
                    ]
                )
            payload = json.loads(output.getvalue())
            self.assertEqual(exit_code, 3)
            self.assertGreater(payload["candidate_count"], 0)
            self.assertEqual(payload["status"], "completed")


if __name__ == "__main__":
    unittest.main()
