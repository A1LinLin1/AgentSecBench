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
EXPORT_SCRIPT = ROOT / "scripts" / "export_paper_tables.py"
FIXTURE = ROOT / "tests" / "fixtures" / "heldout_reproduction"


class ExportPaperTablesTests(unittest.TestCase):
    def test_csv_and_latex_tables_are_exported_from_fixture_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            matrix_dir = temporary_path / "case_matrix"
            ablation_dir = temporary_path / "guard_ablation"
            snapshot_dir = temporary_path / "paper_results"
            tables_dir = temporary_path / "tables"

            subprocess.run(
                [sys.executable, str(MATRIX_SCRIPT), "--input-dir", str(FIXTURE), "--output-dir", str(matrix_dir)],
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
            subprocess.run(
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
            completed = subprocess.run(
                [
                    sys.executable,
                    str(EXPORT_SCRIPT),
                    "--snapshot",
                    str(snapshot_dir / "paper_results_snapshot.json"),
                    "--output-dir",
                    str(tables_dir),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            stdout = json.loads(completed.stdout)
            rq3_tex = (tables_dir / "table_rq3_case_study.tex").read_text(encoding="utf-8")
            rq4_tex = (tables_dir / "table_rq4_guard_ablation.tex").read_text(encoding="utf-8")
            rq3_csv = (tables_dir / "table_rq3_case_study.csv").read_text(encoding="utf-8")
            rq4_csv = (tables_dir / "table_rq4_guard_ablation.csv").read_text(encoding="utf-8")
            notes = (tables_dir / "README.md").read_text(encoding="utf-8")

            self.assertEqual(stdout["rq3_rows"], 2)
            self.assertEqual(stdout["rq4_rows"], 3)
            self.assertIn(r"\begin{table}", rq3_tex)
            self.assertIn(r"\toprule", rq4_tex)
            self.assertIn(r"\label{tab:rq3_case_study}", rq3_tex)
            self.assertIn(r"child\_process.spawn tar", rq3_tex)
            self.assertIn(r"90.0\%", rq4_tex)
            self.assertIn("HSQ-0014", rq3_csv)
            self.assertIn("context_completeness", rq4_csv)
            self.assertIn("booktabs", notes)


if __name__ == "__main__":
    unittest.main()
