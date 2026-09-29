from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from generate_security_adg import make_graph  # noqa: E402
from generate_security_adg_v2 import replace_heuristics  # noqa: E402
from security_adg_dataflow import analyze  # noqa: E402


MANIFEST_ROW = {
    "sample_id": "ASBTEST",
    "repo": "example/agent",
    "git_commit": "0" * 40,
    "experiment_split": "development",
    "use_for_method_tuning": "true",
}


def line_number(source: str, needle: str) -> int:
    for index, line in enumerate(source.splitlines(), start=1):
        if needle in line:
            return index
    raise AssertionError(f"missing line: {needle}")


def finding(source: str, line: int, symbol: str, file_name: str = "agent.py") -> dict:
    stripped = source.splitlines()[line - 1].strip().encode("utf-8")
    return {
        "annotation_id": "SB-ASBTEST-00001",
        "sample_id": "ASBTEST",
        "repo": "example/agent",
        "git_commit": "0" * 40,
        "category": "command_execution",
        "file": file_name,
        "line_start": line,
        "line_end": line,
        "evidence_lines": [line],
        "evidence_line_sha256": [hashlib.sha256(stripped).hexdigest()],
        "match_count": 1,
        "symbol": symbol,
        "evidence": "process invocation",
        "input_origin": "unknown",
        "guard": "unknown",
        "detector": "py_subprocess" if file_name.endswith(".py") else "js_child_process",
        "confidence": "high",
    }


def build_security_adg(source: str, symbol: str, sink_needle: str, file_name: str = "agent.py") -> dict:
    line = line_number(source, sink_needle)
    base = make_graph(finding(source, line, symbol, file_name), MANIFEST_ROW, source, radius=20)
    analysis = analyze(
        source,
        file_name,
        [line],
        symbol=symbol,
        prefer_parameter_sources=True,
        respect_parameter_overwrites=True,
        include_intrinsic_source_operation=False,
    )
    return replace_heuristics(base, analysis, "test_framework_adaptive_generator")


class FrameworkEndToEndGraphTests(unittest.TestCase):
    def assert_graph_framework(self, graph: dict, framework: str, parameter: str) -> None:
        symbol = next(node for node in graph["nodes"] if node["type"] == "agent_or_program_symbol")
        source = next(node for node in graph["nodes"] if node["type"] == "input_source")
        self.assertEqual(symbol["agent_relevance"], "framework_confirmed")
        self.assertIn(framework, symbol["frameworks"])
        self.assertEqual(source["source_type"], "agent_tool_parameter")
        self.assertEqual(source["symbol"], parameter)
        self.assertEqual(source["framework"], framework)
        self.assertIn(framework, graph["views"]["security_adg"]["frameworks"])

    def test_langchain_tool_factory_generates_framework_confirmed_graph(self):
        source = """\
from langchain.tools import Tool
import subprocess
def shell(command: str):
    return subprocess.run(command)
tool = Tool(name="shell", func=shell)
"""
        graph = build_security_adg(source, "shell", "subprocess.run")
        self.assert_graph_framework(graph, "LangChain", "command")

    def test_autogen_registration_generates_framework_confirmed_graph(self):
        source = """\
import subprocess
def run_code(code: str):
    return subprocess.run(code)
assistant.register_for_llm()(run_code)
executor.register_for_execution()(run_code)
"""
        graph = build_security_adg(source, "run_code", "subprocess.run")
        self.assert_graph_framework(graph, "AutoGen", "code")

    def test_typescript_mcp_registration_generates_framework_confirmed_graph(self):
        source = """\
function shell(command: string) {
  return spawn(command);
}
server.tool("shell", shell);
"""
        graph = build_security_adg(source, "shell", "spawn(command)", file_name="agent.ts")
        self.assert_graph_framework(graph, "MCP", "command")


if __name__ == "__main__":
    unittest.main()
