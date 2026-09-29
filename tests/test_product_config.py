from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsecbench import ConfigError, analyze_repository, load_project_config  # noqa: E402
from agentsecbench.cli import main  # noqa: E402


CUSTOM_SOURCE = """\
import acme_agent
import subprocess

@acme_tool
def launch(command: str):
    return subprocess.run(command)
"""

CUSTOM_CONFIG = r"""
[scan]
include = ["src/*.py"]
exclude = ["src/ignored.py"]

[[framework_adapters]]
id = "acme-agent"
name = "Acme Agent"
languages = ["python"]
source_patterns = ['import\s+acme_agent']
decorator_patterns = ['^acme_tool$']
candidate_patterns = ['@acme_tool\b']
confidence = "high"
"""


class ProductConfigTests(unittest.TestCase):
    def test_custom_adapter_affects_discovery_and_graph_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repo"
            (repository / "src").mkdir(parents=True)
            (repository / "src" / "agent.py").write_text(CUSTOM_SOURCE, encoding="utf-8")
            (repository / "src" / "ignored.py").write_text("eval(user_input)\n", encoding="utf-8")
            config_path = repository / ".agentsecbench.toml"
            config_path.write_text(CUSTOM_CONFIG, encoding="utf-8")
            config = load_project_config(repository)
            result = analyze_repository(repository, base / "output", config=config)

            self.assertEqual(result.summary.configuration_file, str(config_path.resolve()))
            self.assertEqual(result.summary.files_scanned, 1)
            self.assertEqual(result.summary.framework_adapter_count, 8)
            self.assertTrue(any("adapter_acme-agent" in detector for finding in result.findings for detector in finding.detectors))
            command_graph = next(graph for graph in result.graphs if any(node.get("category") == "command_execution" for node in graph["nodes"]))
            evidence = command_graph["analysis"]["framework_evidence"]
            self.assertEqual({item["framework"] for item in evidence}, {"Acme Agent"})
            self.assertEqual(evidence[0]["adapter_origin"], "project_config")
            source = next(node for node in command_graph["nodes"] if node["type"] == "input_source")
            self.assertEqual(source["source_type"], "agent_tool_parameter")
            entrypoint_graph = next(
                graph for graph in result.graphs
                if any("adapter_acme-agent" in detector for node in graph["nodes"] for detector in node.get("detectors", []))
            )
            self.assertEqual(entrypoint_graph["views"]["security_adg"]["frameworks"], ["Acme Agent"])
            self.assertGreaterEqual(entrypoint_graph["views"]["security_adg"]["dependency_paths"], 1)

    def test_invalid_regex_is_rejected_with_cli_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            config = repository / "bad.toml"
            config.write_text(
                '[[framework_adapters]]\nid="bad-adapter"\nname="Bad"\ncandidate_patterns=["("]\n',
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_project_config(repository, config)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                exit_code = main(["analyze", str(repository), "--config", str(config)])
            self.assertEqual(exit_code, 2)
            self.assertIn("invalid regex", stderr.getvalue())

    def test_unknown_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            config = repository / ".agentsecbench.toml"
            config.write_text("[scan]\nunknown = true\n", encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "unknown scan keys"):
                load_project_config(repository)

    def test_policy_paths_and_blocking_filters_are_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            config = repository / ".agentsecbench.toml"
            config.write_text(
                "\n".join([
                    "[policy]",
                    'baseline = "policy/baseline.json"',
                    'suppressions = "policy/suppressions.toml"',
                    'blocking_categories = ["command_execution", "filesystem_write"]',
                    'minimum_confidence = "high"',
                    "",
                ]),
                encoding="utf-8",
            )
            loaded = load_project_config(repository)
            self.assertEqual(loaded.baseline_path, (repository / "policy/baseline.json").resolve())
            self.assertEqual(loaded.suppressions_path, (repository / "policy/suppressions.toml").resolve())
            self.assertEqual(loaded.blocking_categories, ("command_execution", "filesystem_write"))
            self.assertEqual(loaded.minimum_confidence, "high")


if __name__ == "__main__":
    unittest.main()
