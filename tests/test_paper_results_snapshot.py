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
SNAPSHOT_SCRIPT = ROOT / "scripts" / "build_paper_results_snapshot.py"
FIXTURE = ROOT / "tests" / "fixtures" / "heldout_reproduction"


class PaperResultsSnapshotTests(unittest.TestCase):
    def test_snapshot_outputs_are_generated_from_fixture_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            matrix_dir = temporary_path / "case_matrix"
            ablation_dir = temporary_path / "guard_ablation"
            snapshot_dir = temporary_path / "paper_results"
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
            subprocess.run(
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
            completed = subprocess.run(
                [
                    sys.executable,
                    str(SNAPSHOT_SCRIPT),
                    "--matrix",
                    str(matrix_dir / "heldout_reproduction_case_matrix.json"),
                    "--ablation",
                    str(ablation_dir / "guard_ablation_summary.json"),
                    "--output-dir",
                    str(snapshot_dir),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            stdout = json.loads(completed.stdout)
            snapshot = json.loads((snapshot_dir / "paper_results_snapshot.json").read_text(encoding="utf-8"))
            overview = (snapshot_dir / "README.md").read_text(encoding="utf-8")
            rq3 = (snapshot_dir / "rq3_case_study_table.md").read_text(encoding="utf-8")
            rq4 = (snapshot_dir / "rq4_guard_ablation_table.md").read_text(encoding="utf-8")
            boundaries = (snapshot_dir / "experiment_claim_boundaries.md").read_text(encoding="utf-8")
            commands = (snapshot_dir / "reproducibility_commands.md").read_text(encoding="utf-8")

            self.assertEqual(stdout["cases"], 2)
            self.assertEqual(stdout["guarded_cases"], 1)
            self.assertEqual(snapshot["headline_numbers"]["confirmed_behavior_cases"], 2)
            self.assertEqual(snapshot["headline_numbers"]["security_adg_guard_visible"], 1)
            self.assertIn("Suggested paper sentence", overview)
            self.assertIn("HSQ-0014", rq3)
            self.assertIn("Security-ADG", rq4)
            self.assertIn("Do not report precision, recall, F1", boundaries)
            self.assertIn("build_paper_results_snapshot.py", commands)


if __name__ == "__main__":
    unittest.main()
