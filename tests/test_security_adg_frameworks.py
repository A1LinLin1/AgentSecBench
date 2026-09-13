from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from security_adg_frameworks import detect_frameworks, detect_python_frameworks  # noqa: E402


def python_evidence(source: str, function_name: str) -> list[dict]:
    tree = ast.parse(source)
    function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == function_name)
    return [item.to_dict() for item in detect_python_frameworks(source, function, tree)]


class SecurityAdgFrameworkAdapterTests(unittest.TestCase):
    def assert_framework(self, evidence: list[dict], framework: str, parameter: str) -> None:
        matches = [item for item in evidence if item["framework"] == framework]
        self.assertTrue(matches, evidence)
        self.assertIn(parameter, matches[0]["parameters"])
        self.assertEqual(matches[0]["semantic_role"], "tool_definition")

    def test_mcp_tool_decorator(self):
        source = """\
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("demo")
@mcp.tool()
def shell(command: str):
    return subprocess.run(command)
"""
        self.assert_framework(python_evidence(source, "shell"), "MCP", "command")

    def test_langchain_tool_factory(self):
        source = """\
from langchain.tools import Tool
def shell(command: str):
    return subprocess.run(command)
tool = Tool(name="shell", func=shell)
"""
        self.assert_framework(python_evidence(source, "shell"), "LangChain", "command")

    def test_langchain_tool_decorator_uses_import_context(self):
        source = """\
from langchain_core.tools import tool
@tool
def shell(command: str):
    return subprocess.run(command)
"""
        self.assert_framework(python_evidence(source, "shell"), "LangChain", "command")

    def test_crewai_basetool_run_method(self):
        source = """\
from crewai.tools import BaseTool
class ShellTool(BaseTool):
    def _run(self, command: str):
        return subprocess.run(command)
"""
        self.assert_framework(python_evidence(source, "_run"), "CrewAI", "command")

    def test_autogen_registration(self):
        source = """\
def run_code(code: str):
    return exec(code)
assistant.register_for_llm()(run_code)
executor.register_for_execution()(run_code)
"""
        self.assert_framework(python_evidence(source, "run_code"), "AutoGen", "code")

    def test_openai_agents_function_tool(self):
        source = """\
from agents import function_tool
@function_tool
def write_file(path: str, content: str):
    Path(path).write_text(content)
"""
        self.assert_framework(python_evidence(source, "write_file"), "OpenAI Agents SDK", "path")

    def test_semantic_kernel_function(self):
        source = """\
from semantic_kernel.functions import kernel_function
@kernel_function
def fetch(url: str):
    return requests.get(url)
"""
        self.assert_framework(python_evidence(source, "fetch"), "Semantic Kernel", "url")

    def test_llamaindex_function_tool(self):
        source = """\
from llama_index.core.tools import FunctionTool
def read_file(path: str):
    return Path(path).read_text()
tool = FunctionTool.from_defaults(fn=read_file)
"""
        self.assert_framework(python_evidence(source, "read_file"), "LlamaIndex", "path")

    def test_typescript_mcp_register_tool(self):
        source = """\
function shell(command: string) {
  return spawn(command);
}
server.tool("shell", shell);
"""
        evidence = detect_frameworks(source, "server.ts", "shell", 2)
        self.assert_framework(evidence, "MCP", "command")


if __name__ == "__main__":
    unittest.main()
