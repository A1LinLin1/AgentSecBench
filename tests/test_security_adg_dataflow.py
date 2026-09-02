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


if __name__ == "__main__":
    unittest.main()
