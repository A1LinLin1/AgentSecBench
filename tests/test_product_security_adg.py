from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsecbench import analyze_repository, validate_graphs  # noqa: E402


PYTHON_TOOL = """\
from mcp.server.fastmcp import FastMCP
import subprocess
mcp = FastMCP("test")

@mcp.tool()
def shell(command: str):
    if command:
        return subprocess.run(command, shell=True)
"""

TYPESCRIPT_TOOL = """\
server.tool("fetch_page", async (url: string) => {
  if (url) {
    return fetch(url);
  }
});
"""


class ProductSecurityAdgTests(unittest.TestCase):
    def test_python_mcp_dependency_guard_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repo"
            repository.mkdir()
            (repository / "tool.py").write_text(PYTHON_TOOL, encoding="utf-8")
            result = analyze_repository(repository, base / "out")
            command_graph = next(
                graph for graph in result.graphs
                if any(node.get("category") == "command_execution" for node in graph["nodes"])
            )
            view = command_graph["views"]["security_adg"]
            self.assertGreaterEqual(view["source_candidates"], 1)
            self.assertGreaterEqual(view["guard_candidates"], 1)
            self.assertGreaterEqual(view["dependency_paths"], 1)
            self.assertIn("MCP", view["frameworks"])
            self.assertTrue(command_graph["provenance"]["evidence_hash_verified"])
            self.assertRegex(command_graph["provenance"]["finding_fingerprint"], r"^ASBFP-[0-9A-F]{24}$")
            self.assertFalse(command_graph["provenance"]["source_execution_used"])

    def test_typescript_graphs_are_structurally_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repo"
            repository.mkdir()
            (repository / "tool.ts").write_text(TYPESCRIPT_TOOL, encoding="utf-8")
            result = analyze_repository(repository, base / "out")
            self.assertTrue(result.graphs)
            self.assertTrue(result.validation["valid"])
            persisted = [json.loads(line) for line in (base / "out" / "security-adg.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(persisted, list(result.graphs))

    def test_validator_rejects_tampered_evidence_and_dangling_edge(self) -> None:
        graph = {
            "graph_id": "g1", "candidate_id": "c1",
            "provenance": {"evidence_hash_verified": False, "label_inputs_used": False, "source_execution_used": False},
            "nodes": [
                {"id": "n1", "type": "agent_or_program_symbol"},
                {"id": "n2", "type": "security_sensitive_operation"},
                {"id": "n3", "type": "external_effect"},
                {"id": "n4", "type": "trust_boundary"},
            ],
            "edges": [{"from": "n4", "to": "missing", "type": "reaches"}],
            "views": {"security_adg": {"nodes": ["n1", "n2", "n3", "n4"], "edges": ["reaches"]}},
        }
        report = validate_graphs((graph,), expected_candidates=1)
        self.assertFalse(report["valid"])
        self.assertEqual({item["code"] for item in report["errors"]}, {"evidence_hash_not_verified", "dangling_edge"})


if __name__ == "__main__":
    unittest.main()
