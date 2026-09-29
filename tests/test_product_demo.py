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

from agentsecbench.cli import main  # noqa: E402
from agentsecbench.demo import DemoError, run_demo  # noqa: E402


class ProductDemoTests(unittest.TestCase):
    def test_demo_builds_authored_project_and_complete_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "demo"
            result = run_demo(output)

            self.assertEqual(result.status, "completed")
            self.assertGreaterEqual(result.candidate_count, 2)
            self.assertEqual(result.candidate_count, result.graph_count)
            self.assertIn("command_execution", result.categories)
            self.assertIn("filesystem_write", result.categories)
            self.assertTrue((output / "sample-agent" / "agent.py").is_file())
            self.assertTrue(Path(result.report_file).is_file())
            self.assertTrue(Path(result.findings_file).is_file())
            self.assertTrue(Path(result.security_adg_file).is_file())

    def test_demo_cli_json_is_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "demo"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["demo", "--output", str(output), "--json"])
            payload = json.loads(stdout.getvalue())

            self.assertEqual(exit_code, 0)
            self.assertEqual(payload["status"], "completed")
            self.assertGreaterEqual(payload["candidate_count"], 2)
            self.assertIn("no vulnerability claim", payload["claim_boundary"])

    def test_demo_refuses_to_overwrite_nonempty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "demo"
            output.mkdir()
            marker = output / "keep.txt"
            marker.write_text("preserve me", encoding="utf-8")

            with self.assertRaisesRegex(DemoError, "not empty"):
                run_demo(output)
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve me")


if __name__ == "__main__":
    unittest.main()
