from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CorpusWideSecurityAdgReportTests(unittest.TestCase):
    def test_fixture_report_keeps_evidence_and_claim_boundaries_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.csv"
            with manifest.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["repo", "ecosystem", "dominant_language"])
                writer.writeheader()
                writer.writerow({"repo": "example/agent", "ecosystem": "LangChain", "dominant_language": "Python"})
                writer.writerow({"repo": "example/mcp", "ecosystem": "MCP", "dominant_language": "TypeScript"})
            output = root / "report"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "build_corpus_wide_security_adg_report.py"),
                    "--manifest", str(manifest),
                    "--graphs", str(ROOT / "tests" / "fixtures" / "security_adg_showcase.jsonl"),
                    "--output-dir", str(output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads((output / "corpus_wide_security_adg_report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["population"]["candidates"], 2)
            self.assertEqual(report["population"]["source_provenance"], 1)
            self.assertEqual(report["population"]["guard_candidate"], 1)
            self.assertEqual(report["population"]["trust_crossing_candidate"], 1)
            self.assertEqual(report["population"]["external_effect_confirmed"], 0)
            self.assertFalse(report["runtime"]["available"])
            self.assertIn("not vulnerability counts", report["claim_boundary"])
            self.assertIn('"candidates": 2', completed.stdout)
            self.assertTrue((output / "by_category.csv").exists())
            markdown = (output / "corpus_wide_security_adg_report.md").read_text(encoding="utf-8")
            self.assertIn("not vulnerability counts", markdown)
            self.assertIn("| command_execution | 1 |", markdown)

    def test_mismatched_runtime_populations_are_not_combined(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        from build_corpus_wide_security_adg_report import runtime_summary

        scan = {
            "candidate_count": 508,
            "execution_metrics": {"wall_seconds": 1.0, "per_repository": [{"repo": "r", "wall_seconds": 1.0}]},
        }
        graph = {
            "graph_count": 531,
            "execution_metrics": {"wall_seconds": 2.0, "per_repository": [{"repo": "r", "wall_seconds": 2.0}]},
        }
        result = runtime_summary(scan, graph, 531)
        self.assertFalse(result["population_consistent"])
        self.assertFalse(result["end_to_end_comparable"])
        self.assertEqual(result["per_repository"], [])


if __name__ == "__main__":
    unittest.main()
