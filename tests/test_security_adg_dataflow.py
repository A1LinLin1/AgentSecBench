from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from security_adg_dataflow import analyze_python, analyze_typescript  # noqa: E402


class PythonDataflowTests(unittest.TestCase):
    def test_parameter_assignment_chain_and_dominating_guard(self):
        source = """\
import subprocess
def execute(action):
    command = action.get("command")
    args = ["bash", "-lc", command]
    if command:
        return subprocess.run(args)
"""
        result = analyze_python(source, [6])
        self.assertTrue(any(item["symbol"] == "action" for item in result.sources))
        self.assertTrue(any(path[-1] == "action" for path in result.dependency_paths))
        self.assertTrue(any(item["kind"] == "dominating_if" for item in result.guards))

    def test_constant_operation_has_no_input_source(self):
        source = """\
import subprocess
def healthcheck():
    return subprocess.run(["echo", "ok"])
"""
        result = analyze_python(source, [3])
        self.assertEqual(result.sources, [])
        self.assertEqual(result.dependency_paths, [])

    def test_mcp_tool_parameter_reaches_body_operation(self):
        source = """\
@mcp.tool()
def shell_exec(command: str):
    return subprocess.Popen(command, shell=True)
"""
        result = analyze_python(source, [1], symbol="shell_exec")
        self.assertEqual(result.operation_line, 3)
        self.assertTrue(any(item["source_type"] == "agent_tool_parameter" for item in result.sources))
        self.assertTrue(any(path[-1] == "command" for path in result.dependency_paths))

    def test_parameter_precedence_avoids_duplicate_source_api(self):
        source = """\
import subprocess
def execute(request):
    command = request.get("command")
    return subprocess.run(command)
"""
        result = analyze_python(source, [4], prefer_parameter_sources=True)
        self.assertEqual({item["symbol"] for item in result.sources}, {"request"})
        self.assertEqual({item["source_type"] for item in result.sources}, {"function_parameter"})

    def test_parameter_constant_overwrite_is_not_external_dependency_in_v2_3(self):
        source = """\
import subprocess
def execute(command):
    command = "echo safe"
    return subprocess.run(command)
"""
        result = analyze_python(source, [4], respect_parameter_overwrites=True)
        self.assertEqual(result.sources, [])
        self.assertEqual(result.dependency_paths, [])

    def test_parameter_self_transformation_remains_dependency_in_v2_3(self):
        source = """\
import subprocess
def execute(command):
    command = command.strip()
    return subprocess.run(command)
"""
        result = analyze_python(source, [4], respect_parameter_overwrites=True)
        self.assertTrue(any(item["symbol"] == "command" for item in result.sources))

    def test_network_sink_is_not_an_intrinsic_source_in_v2_4(self):
        source = """\
import requests
def fetch_url(url):
    return requests.get(url)
"""
        result = analyze_python(source, [3], include_intrinsic_source_operation=False)
        self.assertEqual({item["source_type"] for item in result.sources}, {"function_parameter"})
        self.assertEqual({item["symbol"] for item in result.sources}, {"url"})

    def test_langchain_tool_parameter_is_framework_confirmed_agent_source(self):
        source = """\
from langchain.tools import Tool
import subprocess
def shell(command: str):
    return subprocess.run(command)
tool = Tool(name="shell", func=shell)
"""
        result = analyze_python(source, [4], symbol="shell")
        self.assertTrue(any(item["source_type"] == "agent_tool_parameter" for item in result.sources))
        self.assertTrue(any(item.get("framework") == "LangChain" for item in result.sources))
        self.assertTrue(any(item["framework"] == "LangChain" for item in result.framework_evidence))

    def test_crewai_basetool_parameter_is_framework_confirmed_agent_source(self):
        source = """\
from crewai.tools import BaseTool
import subprocess
class ShellTool(BaseTool):
    def _run(self, command: str):
        return subprocess.run(command)
"""
        result = analyze_python(source, [5], symbol="_run")
        self.assertTrue(any(item["source_type"] == "agent_tool_parameter" for item in result.sources))
        self.assertTrue(any(item.get("framework") == "CrewAI" for item in result.sources))


class TypeScriptDataflowTests(unittest.TestCase):
    def test_parameter_reaches_operation_through_assignment(self):
        source = """\
async function execute(command: string) {
  const args = ["-lc", command];
  if (command) {
    return spawn("bash", args);
  }
}
"""
        result = analyze_typescript(source, [4])
        self.assertTrue(any(item["symbol"] == "command" for item in result.sources))
        self.assertTrue(result.dependency_paths)
        self.assertTrue(result.guards)

    def test_mcp_registered_typescript_tool_parameter_is_agent_source(self):
        source = """\
function shell(command: string) {
  return spawn(command);
}
server.tool("shell", shell);
"""
        result = analyze_typescript(source, [2])
        self.assertTrue(any(item["source_type"] == "agent_tool_parameter" for item in result.sources))
        self.assertTrue(any(item.get("framework") == "MCP" for item in result.sources))

    def test_template_literal_preserves_embedded_dependency(self):
        source = """\
function preview(templateId: string) {
  return fetch(`/api/templates/${encodeURIComponent(templateId)}/example`);
}
"""
        result = analyze_typescript(source, [2], respect_parameter_overwrites=True)
        self.assertTrue(any(item["symbol"] == "templateId" for item in result.sources))

    def test_react_state_flows_into_multiline_fetch_body(self):
        source = """\
function SettingsModal() {
  const [source, setSource] = useState("");
  const onInstall = async () => {
    const spec = source.trim();
    return fetch("/api/marketplace/install", {
      method: "POST",
      body: JSON.stringify({ source: spec }),
    });
  };
}
"""
        result = analyze_typescript(source, [5], respect_parameter_overwrites=True)
        self.assertTrue(any(item["source_type"] == "ui_state" and item["symbol"] == "source" for item in result.sources))
        self.assertTrue(any(path[-1] == "source" for path in result.dependency_paths))

    def test_for_of_variable_flows_to_filesystem_read(self):
        source = """\
async function convert(positional: string[]) {
  const inputPaths = positional.length > 0 ? positional : [];
  for (const inputPath of inputPaths) {
    const content = fs.readFileSync(inputPath, "utf-8");
  }
}
"""
        result = analyze_typescript(source, [4], respect_parameter_overwrites=True)
        self.assertTrue(any(item["symbol"] == "positional" for item in result.sources))
        self.assertTrue(any(path[-1] == "positional" for path in result.dependency_paths))


if __name__ == "__main__":
    unittest.main()
