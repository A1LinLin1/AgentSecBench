import unittest

from scripts.build_reproduction_gt_findings import finding_id_for_gt, make_finding
from scripts.evaluate_reproduction_gt_coverage import evaluate


class ReproductionGtCoverageTests(unittest.TestCase):
    def test_finding_id_for_gt_is_stable(self):
        self.assertEqual(finding_id_for_gt("ASE-0001-0006.runtime_stub"), "RGT-ASE-0001-0006-runtime_stub")

    def test_make_finding_preserves_gt_metadata_without_labels(self):
        gt = {
            "gt_id": "ALR-001",
            "repository": "owner/repo",
            "frozen_commit": "abc",
            "candidate_file": "src/a.py",
            "candidate_line": 1,
            "evidence_operation_line": 2,
            "evidence_operation_line_source": "subprocess_run_call_ast",
            "behavior_category": "command_execution",
            "behavior_ground_truth": True,
            "vulnerability_ground_truth": True,
        }
        source = "def run(cmd):\n    return subprocess.run(cmd)\n"
        finding = make_finding(gt, source, "2026-01-01T00:00:00+00:00")
        self.assertEqual(finding["annotation_id"], "RGT-ALR-001")
        self.assertEqual(finding["line_start"], 2)
        self.assertEqual(finding["source_candidate_line"], 1)
        self.assertEqual(finding["source_gt_id"], "ALR-001")
        self.assertTrue(finding["behavior_ground_truth"])
        self.assertTrue(finding["vulnerability_ground_truth"])
        self.assertNotIn("human", finding)

    def test_evaluate_reports_recall_style_coverage(self):
        gt_rows = [
            {
                "gt_id": "ALR-001",
                "repository": "owner/repo",
                "candidate_file": "src/a.py",
                "candidate_line": 2,
                "behavior_category": "command_execution",
                "behavior_ground_truth": True,
                "vulnerability_ground_truth": True,
            },
            {
                "gt_id": "ALR-002",
                "repository": "owner/repo",
                "candidate_file": None,
                "candidate_line": None,
                "behavior_category": "command_execution",
                "behavior_ground_truth": True,
                "vulnerability_ground_truth": False,
            },
        ]
        graphs = [
            {
                "candidate_id": "RGT-ALR-001",
                "views": {"security_adg": {"source_candidates": 1, "dependency_paths": 1, "guard_candidates": 0}},
                "analysis": {"framework_evidence": []},
            }
        ]
        rows, summary = evaluate(gt_rows, graphs)
        self.assertEqual(summary["cases"], 2)
        self.assertEqual(summary["evaluable_cases"], 1)
        self.assertEqual(summary["overall"]["dependency_path_coverage"], 1.0)
        self.assertTrue(rows[0]["graph_present"])
        self.assertFalse(rows[1]["evaluable"])


if __name__ == "__main__":
    unittest.main()
