from __future__ import annotations

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

from agentsecbench import analyze_repository  # noqa: E402


MCP_SOURCE = """\
from mcp.server.fastmcp import FastMCP
import subprocess

mcp = FastMCP("coverage-demo")

@mcp.tool()
def shell(command: str):
    return subprocess.run(command, shell=True)
"""

GENERIC_SOURCE = """\
from pathlib import Path

def save(path: str, content: str):
    Path(path).write_text(content, encoding="utf-8")
"""


def report_payload(page: str) -> dict:
    match = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', page, re.DOTALL)
    if not match:
        raise AssertionError("report payload missing")
    return json.loads(match.group(1))


class ProductFrameworkCoverageTests(unittest.TestCase):
    def test_coverage_separates_modeled_signal_only_and_generic_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            (repository / "mcp_agent.py").write_text(MCP_SOURCE, encoding="utf-8")
            (repository / "generic.py").write_text(GENERIC_SOURCE, encoding="utf-8")
            (repository / "unused_langchain.py").write_text("import langchain\n", encoding="utf-8")

            result = analyze_repository(repository, base / "output")
            coverage_path = Path(result.summary.framework_coverage_file)
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
            adapters = {item["adapter_id"]: item for item in coverage["adapters"]}

            self.assertEqual(adapters["mcp"]["status"], "modeled")
            self.assertGreaterEqual(adapters["mcp"]["modeled_candidate_count"], 1)
            self.assertEqual(adapters["langchain"]["status"], "signal_only")
            self.assertIn("unused_langchain.py", adapters["langchain"]["signal_files"])
            self.assertIn("generic.py", coverage["generic_candidate_files"])
            self.assertGreaterEqual(coverage["generic_candidate_file_count"], 1)
            self.assertEqual(
                result.summary.framework_signal_file_count,
                coverage["framework_signal_file_count"],
            )

            page = Path(result.summary.report_file).read_text(encoding="utf-8")
            payload = report_payload(page)
            self.assertEqual(payload["frameworkCoverage"], coverage)
            self.assertIn("Framework coverage diagnostics", page)


if __name__ == "__main__":
    unittest.main()
