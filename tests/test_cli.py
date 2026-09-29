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
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsecbench import ConfigError, __version__, initialize_project, load_project_config  # noqa: E402
from agentsecbench.cli import build_doctor_report, main  # noqa: E402


class CliTests(unittest.TestCase):
    def test_public_version_is_pre_release(self) -> None:
        self.assertEqual(__version__, "0.1.1")

    def test_doctor_report_has_stable_schema(self) -> None:
        report = build_doctor_report().to_dict()
        self.assertEqual(report["schema_version"], "1.0")
        self.assertEqual(report["agentsecbench_version"], __version__)
        self.assertTrue(report["python_supported"])
        self.assertEqual(
            [item["name"] for item in report["optional_tools"]],
            ["git", "docker", "semgrep", "codeql", "dot"],
        )

    def test_doctor_json_is_machine_readable(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(["doctor", "--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "ready")
        self.assertIn("python_version", payload)

    def test_no_arguments_prints_help(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main([])
        self.assertEqual(exit_code, 0)
        self.assertIn("doctor", output.getvalue())

    def test_init_creates_valid_config_and_reports_next_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main(["init", str(project), "--json"])
            payload = json.loads(output.getvalue())
            config = load_project_config(project)
            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["status"], "initialized")
            self.assertFalse(payload["overwritten"])
            self.assertTrue((project / ".agentsecbench.toml").is_file())
            self.assertTrue(config.interprocedural)
            self.assertIn("node_modules/**", config.exclude)
            self.assertIn("agentsecbench analyze", payload["next_command"])

    def test_init_refuses_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            initialize_project(project)
            config_path = project / ".agentsecbench.toml"
            original = config_path.read_text(encoding="utf-8")
            with self.assertRaisesRegex(ConfigError, "use --force"):
                initialize_project(project)
            self.assertEqual(config_path.read_text(encoding="utf-8"), original)
            replaced = initialize_project(project, force=True)
            self.assertTrue(replaced.overwritten)


if __name__ == "__main__":
    unittest.main()
