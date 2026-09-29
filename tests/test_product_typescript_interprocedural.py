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
import { exec } from "node:child_process";
export function execute(value: string) {
  return exec(value);
}
"""

ENTRYPOINT = """\
import { execute } from "./helper";
export async function shell(command: string) {
  return execute(command);
}
server.tool("shell", shell);
"""


class ProductTypeScriptInterproceduralTests(unittest.TestCase):
    def make_repo(self, base: Path, entrypoint: str = ENTRYPOINT) -> Path:
        repository = base / "repo"
        repository.mkdir()
        (repository / "helper.ts").write_text(HELPER, encoding="utf-8")
        (repository / "agent.ts").write_text(entrypoint, encoding="utf-8")
        return repository

    def command_graph(self, result):
        return next(
            graph for graph in result.graphs
            if graph["provenance"]["file"] == "helper.ts"
            and any(node.get("category") == "command_execution" for node in graph["nodes"])
        )

    def test_named_import_reaches_mcp_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            result = analyze_repository(self.make_repo(base), base / "output")
            graph = self.command_graph(result)
            interprocedural = graph["analysis"]["interprocedural"]
            source = next(node for node in graph["nodes"] if node["type"] == "input_source")
            self.assertEqual(interprocedural["language"], "javascript_typescript")
            self.assertEqual(interprocedural["expanded_sources"], 1)
            self.assertEqual(source["file"], "agent.ts")
            self.assertEqual(source["symbol"], "command")
            self.assertEqual(source["framework"], "MCP")
            self.assertIn("MCP", graph["views"]["security_adg"]["frameworks"])
            self.assertEqual(
                [node["name"] for node in graph["nodes"] if node["type"] == "program_symbol"],
                ["agent.ts:shell"],
            )

    def test_namespace_import_and_two_hop_flow(self) -> None:
        entrypoint = """\
import * as service from "./service";
export async function shell(command: string) {
  return service.dispatch(command);
}
server.tool("shell", shell);
"""
        service = """\
import { execute } from "./helper";
export const dispatch = (payload: string) => {
  return execute(payload);
};
"""
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = self.make_repo(base, entrypoint)
            (repository / "service.ts").write_text(service, encoding="utf-8")
            graph = self.command_graph(analyze_repository(repository, base / "output"))
            source = next(node for node in graph["nodes"] if node["type"] == "input_source")
            self.assertEqual(source["call_depth"], 2)
            self.assertEqual(
                [node["name"] for node in graph["nodes"] if node["type"] == "program_symbol"],
                ["agent.ts:shell", "service.ts:dispatch"],
            )

    def test_constant_argument_does_not_create_agent_source(self) -> None:
        entrypoint = ENTRYPOINT.replace("execute(command)", 'execute("date")')
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            graph = self.command_graph(analyze_repository(self.make_repo(base, entrypoint), base / "output"))
            self.assertEqual(graph["analysis"]["interprocedural"]["expanded_sources"], 0)
            self.assertFalse(any(node.get("interprocedural") for node in graph["nodes"]))


if __name__ == "__main__":
    unittest.main()
