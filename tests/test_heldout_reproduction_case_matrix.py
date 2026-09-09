from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_heldout_reproduction_case_matrix.py"
FIXTURE = ROOT / "tests" / "fixtures" / "heldout_reproduction"


class HeldoutReproductionCaseMatrixTests(unittest.TestCase):
    def test_matrix_outputs_are_generated_from_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "case_matrix"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--input-dir",
                    str(FIXTURE),
                    "--output-dir",
                    str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            stdout = json.loads(completed.stdout)
            matrix = json.loads((output / "heldout_reproduction_case_matrix.json").read_text(encoding="utf-8"))
            markdown = (output / "heldout_reproduction_case_matrix.md").read_text(encoding="utf-8")
            csv_text = (output / "heldout_reproduction_case_matrix.csv").read_text(encoding="utf-8")
            html_text = (output / "heldout_reproduction_case_study.html").read_text(encoding="utf-8")

            self.assertEqual(stdout["cases"], 2)
            self.assertTrue(stdout["outputs"]["html"].endswith("heldout_reproduction_case_study.html"))
            self.assertEqual(matrix["case_count"], 2)
            self.assertEqual(matrix["status_groups"]["confirmed_behavior"], 2)
            self.assertEqual(matrix["repositories"]["dddabtc/winremote-mcp"], 1)
            self.assertEqual(matrix["repositories"]["nexu-io/html-anything"], 1)
            self.assertEqual(matrix["guard_postures"]["guarded"], 1)
            self.assertEqual(matrix["guard_postures"]["no_guard_confirmed"], 1)
            self.assertIn("PowerShell -Command", markdown)
            self.assertIn("child_process.spawn tar", markdown)
            self.assertIn("HSQ-0300", csv_text)
            self.assertIn("Held-out reproduction case study", html_text)
            self.assertIn("repoFilter", html_text)
            self.assertIn("guardFilter", html_text)
            self.assertIn("HSQ-0014", html_text)
            self.assertIn("HSQ-0300", html_text)


if __name__ == "__main__":
    unittest.main()
