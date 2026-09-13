import unittest

from scripts.build_reproduction_ground_truth import (
    build_ground_truth,
    explicit_not_vulnerability,
    infer_behavior_category,
    infer_proof_types,
    infer_candidate_coordinate,
    infer_operation_line,
    vulnerability_ground_truth,
)


class ReproductionGroundTruthTests(unittest.TestCase):
    def test_boundary_and_impact_are_required_for_vulnerability_gt(self):
        records = [
            {
                "status": "confirmed_source_and_documentation_boundary_for_unauthenticated_python_evaluator_code_execution",
            },
            {
                "status": "confirmed_local_code_metric_execution",
                "marker_seen": True,
            },
        ]
        self.assertEqual(
            vulnerability_ground_truth(records),
            (True, "confirmed_boundary_and_impact_reproduction"),
        )

    def test_explicit_not_vulnerability_overrides_confirmed_behavior(self):
        records = [
            {
                "status": "confirmed_mcp_tool_parameter_to_powershell_command_argument",
                "not_a_vulnerability_claim": True,
            }
        ]
        self.assertEqual(
            vulnerability_ground_truth(records),
            (False, "explicit_not_a_vulnerability_claim"),
        )

    def test_nested_claim_boundary_not_vulnerability_is_respected(self):
        records = [
            {
                "status": "confirmed_openclaw_agent_probe_spawn_path_platform_conditional_shell",
                "claim_boundary": {
                    "classification": "source-level platform-conditional process invocation",
                    "not_a_vulnerability_claim": True,
                },
            }
        ]
        self.assertTrue(explicit_not_vulnerability(records))
        self.assertEqual(
            vulnerability_ground_truth(records),
            (False, "explicit_not_a_vulnerability_claim"),
        )

    def test_behavior_gt_is_built_without_human_or_model_labels(self):
        rows = build_ground_truth(
            [
                (
                    type("P", (), {"name": "ALR-001.latest.json", "relative_to": lambda self, _base: "evidence.json"})(),
                    {
                        "reproduction_id": "ALR-001",
                        "repository": "owner/repo",
                        "frozen_commit": "abc",
                        "status": "confirmed_local_code_metric_execution",
                        "marker_seen": True,
                    },
                )
            ]
        )
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["behavior_ground_truth"])
        self.assertFalse(rows[0]["human_labels_used"])
        self.assertFalse(rows[0]["model_labels_used"])
        self.assertFalse(rows[0]["vulnerability_ground_truth"])

    def test_infers_effectful_operation_line_from_call_ast(self):
        line, source = infer_operation_line(
            [
                {
                    "candidate_line": 10,
                    "subprocess_run_call_ast": {"line": 42, "callee": "subprocess.run"},
                    "wrapper_call_ast": {"line": 12, "callee": "helper"},
                }
            ]
        )
        self.assertEqual(line, 42)
        self.assertEqual(source, "subprocess_run_call_ast")

    def test_infers_coordinate_from_any_grouped_record(self):
        file_name, line, source = infer_candidate_coordinate(
            [
                {"status": "confirmed_local"},
                {"candidate_file": "tools/interpreter.py", "candidate_line": 16},
            ]
        )
        self.assertEqual(file_name, "tools/interpreter.py")
        self.assertEqual(line, 16)
        self.assertEqual(source, "candidate_file_and_line")

    def test_infers_representative_coordinate_from_candidate_lists(self):
        file_name, line, source = infer_candidate_coordinate(
            [
                {
                    "candidate_files": ["src/a.py", "src/b.py"],
                    "candidate_lines": [10, 20],
                }
            ]
        )
        self.assertEqual(file_name, "src/a.py")
        self.assertEqual(line, 10)
        self.assertEqual(source, "representative_from_candidate_files_and_lines")

    def test_documented_workflow_counts_as_source_and_reachability_proof(self):
        self.assertEqual(
            infer_proof_types(
                {
                    "status": "confirmed_documented_workflow_interpreter_tool_exposure",
                    "readme_signals": {"readme_points_to_workflow_folder": True},
                    "workflow_records": [{"interpreter_tool_connected_to_llm_tools_input": True}],
                }
            ),
            ["boundary_or_reachability", "source_trace"],
        )

    def test_eval_category_is_not_overridden_by_negative_shell_boundary_text(self):
        self.assertEqual(
            infer_behavior_category(
                {
                    "status": "confirmed_guarded_sandboxed_expression_eval_boundary",
                    "operation": "eval(compile(tree, '<workflow-code>', 'eval'), {'__builtins__': {}}, namespace)",
                    "claim_boundary": {
                        "why_not_cve_ready": [
                            "No sandbox bypass, shell execution, file write, network access, or untrusted boundary is established."
                        ]
                    },
                }
            ),
            "dynamic_code_execution",
        )

    def test_executed_text_does_not_imply_dynamic_code_execution(self):
        self.assertEqual(
            infer_behavior_category(
                {
                    "status": "confirmed_guarded_fixed_local_streamlit_launcher_boundary",
                    "operation": "subprocess.run(cmd, check=True) starts fixed Streamlit frontend argv",
                    "claim_boundary": {
                        "why_not_cve_ready": [
                            "No real subprocess executed.",
                            "No command fragment reaches this subprocess.",
                        ]
                    },
                }
            ),
            "command_execution",
        )


if __name__ == "__main__":
    unittest.main()
