from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsecbench import analyze_repository  # noqa: E402


HELPER = """\
import subprocess

def execute(value: str):
    return subprocess.run(value)
"""

ENTRYPOINT = """\
from mcp.server.fastmcp import FastMCP
from helper import execute
mcp = FastMCP("demo")

@mcp.tool()
def shell(command: str):
    return execute(command)
"""


class ProductInterproceduralTests(unittest.TestCase):
    def make_repo(self, base: Path, entrypoint: str = ENTRYPOINT) -> Path:
        repository = base / "repo"
        repository.mkdir()
        (repository / "helper.py").write_text(HELPER, encoding="utf-8")
        (repository / "agent.py").write_text(entrypoint, encoding="utf-8")
        return repository

    def command_graph(self, result):
        return next(
            graph for graph in result.graphs
            if graph["provenance"]["file"] == "helper.py"
            and any(node.get("category") == "command_execution" for node in graph["nodes"])
        )

    def test_cross_file_agent_parameter_reaches_helper_sink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            result = analyze_repository(self.make_repo(base), base / "output")
            graph = self.command_graph(result)
            interprocedural = graph["analysis"]["interprocedural"]
            sources = [node for node in graph["nodes"] if node["type"] == "input_source"]

            self.assertEqual(interprocedural["expanded_sources"], 1)
            self.assertEqual(interprocedural["python_files_indexed"], 2)
            self.assertEqual(result.summary.graphs_with_interprocedural_source, 1)
            self.assertEqual(sources[0]["source_type"], "agent_tool_parameter")
            self.assertEqual(sources[0]["file"], "agent.py")
            self.assertEqual(sources[0]["framework"], "MCP")
            self.assertTrue(sources[0]["interprocedural"])
            self.assertIn("MCP", graph["views"]["security_adg"]["frameworks"])
            chain_nodes = [node for node in graph["nodes"] if node["type"] == "program_symbol"]
            self.assertEqual([node["name"] for node in chain_nodes], ["agent.py:shell"])
            self.assertTrue(any(edge["type"] == "flows_through" for edge in graph["edges"]))
            paths = graph["analysis"]["dependency_paths"]
            self.assertTrue(any("agent.py:shell" in path for path in paths))
            self.assertFalse(any(path[-1] == "value" for path in paths))

    def test_transformed_argument_preserves_parameter_dependency(self) -> None:
        entrypoint = ENTRYPOINT.replace("return execute(command)", "return execute(normalize(command))")
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            graph = self.command_graph(analyze_repository(self.make_repo(base, entrypoint), base / "output"))
            self.assertEqual(graph["analysis"]["interprocedural"]["expanded_sources"], 1)

    def test_two_hop_cross_file_keyword_flow(self) -> None:
        entrypoint = """\
from mcp.server.fastmcp import FastMCP
from service import dispatch
mcp = FastMCP("demo")
@mcp.tool()
def shell(command: str):
    return dispatch(payload=command)
"""
        service = """\
from helper import execute
def dispatch(payload: str):
    return execute(value=payload)
"""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = self.make_repo(base, entrypoint)
            (repository / "service.py").write_text(service, encoding="utf-8")
            graph = self.command_graph(analyze_repository(repository, base / "output"))
            self.assertEqual(graph["analysis"]["interprocedural"]["expanded_sources"], 1)
            source = next(node for node in graph["nodes"] if node["type"] == "input_source")
            self.assertEqual(source["call_depth"], 2)
            chain = [node["name"] for node in graph["nodes"] if node["type"] == "program_symbol"]
            self.assertEqual(chain, ["agent.py:shell", "service.py:dispatch"])
            self.assertTrue(any("service.py:dispatch" in path and "agent.py:shell" in path for path in graph["analysis"]["dependency_paths"]))

    def test_constant_argument_does_not_create_agent_source(self) -> None:
        entrypoint = ENTRYPOINT.replace("return execute(command)", 'return execute("date")')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            graph = self.command_graph(analyze_repository(self.make_repo(base, entrypoint), base / "output"))
            self.assertEqual(graph["analysis"]["interprocedural"]["expanded_sources"], 0)
            self.assertFalse(any(node.get("interprocedural") for node in graph["nodes"]))

    def test_recursive_call_cycle_terminates(self) -> None:
        entrypoint = """\
from helper import execute
def first(value):
    return second(value)
def second(value):
    return first(value)
def start():
    return execute("constant")
"""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            graph = self.command_graph(analyze_repository(self.make_repo(base, entrypoint), base / "output"))
            self.assertEqual(graph["analysis"]["interprocedural"]["expanded_sources"], 0)


if __name__ == "__main__":
    unittest.main()
