from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX_SCRIPT = ROOT / "scripts" / "build_heldout_reproduction_case_matrix.py"
ABLATION_SCRIPT = ROOT / "scripts" / "build_guard_ablation_table.py"
FIXTURE = ROOT / "tests" / "fixtures" / "heldout_reproduction"


class GuardAblationTableTests(unittest.TestCase):
    def test_guard_ablation_outputs_are_generated_from_fixture_matrix(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            matrix_dir = temporary_path / "case_matrix"
            ablation_dir = temporary_path / "guard_ablation"
            subprocess.run(
                [
                    sys.executable,
                    str(MATRIX_SCRIPT),
                    "--input-dir",
                    str(FIXTURE),
                    "--output-dir",
                    str(matrix_dir),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ABLATION_SCRIPT),
                    "--matrix",
                    str(matrix_dir / "heldout_reproduction_case_matrix.json"),
                    "--output-dir",
                    str(ablation_dir),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            stdout = json.loads(completed.stdout)
            summary = json.loads((ablation_dir / "guard_ablation_summary.json").read_text(encoding="utf-8"))
            markdown = (ablation_dir / "guard_ablation_table.md").read_text(encoding="utf-8")
            view_csv = (ablation_dir / "guard_ablation_view_table.csv").read_text(encoding="utf-8")
            case_csv = (ablation_dir / "guard_ablation_case_view_table.csv").read_text(encoding="utf-8")

            self.assertEqual(stdout["cases"], 2)
            self.assertEqual(stdout["guarded_cases"], 1)
            self.assertEqual(summary["case_count"], 2)
            self.assertEqual(summary["headline"]["sink_only_guard_visible"], 0)
            self.assertEqual(summary["headline"]["plain_adg_guard_visible"], 0)
            self.assertEqual(summary["headline"]["security_adg_guard_visible"], 1)
            self.assertEqual(len(summary["view_rows"]), 3)
            self.assertEqual(len(summary["case_view_rows"]), 6)
            self.assertIn("Sink-only", markdown)
            self.assertIn("Security-ADG", markdown)
            self.assertIn("guard_ablation_summary.json", completed.stdout)
            self.assertIn("context_completeness", view_csv)
            self.assertIn("HSQ-0300", case_csv)


if __name__ == "__main__":
    unittest.main()
