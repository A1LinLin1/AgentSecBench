from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsecbench import ScanOptions, analyze_repository  # noqa: E402
from agentsecbench.evaluation import (  # noqa: E402
    EvaluationError,
    compare_interprocedural_graphs,
    markdown_report,
)


BENCHMARK = ROOT / "benchmarks" / "security_adg_micro" / "v4_interprocedural"


class InterproceduralDeltaTests(unittest.TestCase):
    def paired_report(self, temporary: str) -> dict:
        base = Path(temporary)
        baseline = analyze_repository(
            BENCHMARK,
            base / "intraprocedural",
            options=ScanOptions(interprocedural=False),
        )
        enhanced = analyze_repository(
            BENCHMARK,
            base / "interprocedural",
            options=ScanOptions(interprocedural=True),
        )
        return compare_interprocedural_graphs(
            baseline.graphs,
            enhanced.graphs,
            baseline.summary.to_dict(),
            enhanced.summary.to_dict(),
        )

    def test_paired_benchmark_recovers_python_and_typescript_two_hop_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self.paired_report(temporary)

        self.assertTrue(report["population_alignment"]["candidate_ids_equal"])
        self.assertEqual(report["population_alignment"]["candidate_count"], 10)
        self.assertEqual(report["changed_candidate_count"], 2)
        self.assertEqual(
            report["language_source_contributions"],
            {"javascript_typescript": 1, "python": 1},
        )
        self.assertEqual(report["call_depth_distribution"], {"2": 2})
        self.assertEqual(report["path_refinement"]["added_interprocedural_paths"], 2)
        self.assertEqual(report["path_refinement"]["replaced_intraprocedural_paths"], 2)
        changed_files = {item["file"] for item in report["candidate_deltas"]}
        self.assertEqual(
            changed_files,
            {"python_positive/helper.py", "typescript_positive/helper.ts"},
        )
        self.assertFalse(any("constant" in file for file in changed_files))
        self.assertIn("not precision, recall, or vulnerability ground truth", report["claim_boundary"])

    def test_markdown_is_an_auditable_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rendered = markdown_report(self.paired_report(temporary))
        self.assertIn("Interprocedural Security-ADG Delta", rendered)
        self.assertIn("Path refinement", rendered)
        self.assertIn("python_positive/helper.py", rendered)
        self.assertIn("typescript_positive/helper.ts", rendered)

    def test_population_mismatch_refuses_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            result = analyze_repository(
                BENCHMARK,
                base / "graphs",
                options=ScanOptions(interprocedural=False),
            )
        enhanced = list(copy.deepcopy(result.graphs))
        enhanced.pop()
        with self.assertRaisesRegex(EvaluationError, "candidate populations differ"):
            compare_interprocedural_graphs(result.graphs, tuple(enhanced))


if __name__ == "__main__":
    unittest.main()
