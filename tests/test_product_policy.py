from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsecbench import analyze_repository  # noqa: E402
from agentsecbench.cli import main  # noqa: E402
from agentsecbench.policy import (  # noqa: E402
    PolicyError,
    evaluate_policy,
    load_suppressions,
    policy_markdown,
    write_baseline,
)


SOURCE = """\
import subprocess

def run(command):
    return subprocess.run(command)
"""


class ProductPolicyTests(unittest.TestCase):
    def test_stable_fingerprint_survives_line_movement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            source = repository / "agent.py"
            source.write_text(SOURCE, encoding="utf-8")
            first = analyze_repository(repository, base / "first")
            source.write_text("\n\n" + SOURCE, encoding="utf-8")
            second = analyze_repository(repository, base / "second")
        first_command = next(item for item in first.findings if item.category == "command_execution")
        second_command = next(item for item in second.findings if item.category == "command_execution")
        self.assertNotEqual(first_command.finding_id, second_command.finding_id)
        self.assertEqual(first_command.fingerprint, second_command.fingerprint)

    def test_baseline_new_and_auditable_suppression_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            source = repository / "agent.py"
            source.write_text(SOURCE, encoding="utf-8")
            initial = analyze_repository(repository, base / "initial")
            baseline_path = base / "baseline.json"
            write_baseline(base / "initial" / "findings.jsonl", baseline_path)

            source.write_text(SOURCE + "\ndef evaluate(code):\n    return eval(code)\n", encoding="utf-8")
            current = analyze_repository(repository, base / "current")
            report = evaluate_policy(current.findings, baseline_path=baseline_path)
            self.assertEqual(report["existing_findings"], len(initial.findings))
            self.assertEqual(report["new_findings"], 1)
            new_finding = next(
                finding for finding in current.findings
                if finding.fingerprint not in {item.fingerprint for item in initial.findings}
            )
            suppressions = base / "suppressions.toml"
            suppressions.write_text(
                "\n".join([
                    'schema_version = "1.0"',
                    "",
                    "[[suppressions]]",
                    'id = "accepted-generated-evaluator"',
                    f'fingerprint = "{new_finding.fingerprint}"',
                    'reason = "Generated test evaluator is isolated from agent input"',
                    'owner = "security-team"',
                    'expires = "2099-12-31"',
                    "",
                ]),
                encoding="utf-8",
            )
            suppressed = evaluate_policy(
                current.findings,
                baseline_path=baseline_path,
                suppressions_path=suppressions,
                today=date(2026, 1, 1),
            )
            self.assertEqual(suppressed["suppressed_findings"], 1)
            self.assertEqual(suppressed["new_unsuppressed_findings"], 0)

    def test_suppression_requires_reason_and_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "suppressions.toml"
            path.write_text(
                'schema_version = "1.0"\n[[suppressions]]\nid = "bad"\nfingerprint = "ASBFP-X"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PolicyError, "requires non-empty"):
                load_suppressions(path)

    def test_cli_fail_on_new_uses_exit_four_and_writes_policy_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            (repository / "agent.py").write_text(SOURCE, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main([
                    "analyze", str(repository), "--output", str(base / "results"),
                    "--fail-on-new", "--json",
                ])
            payload = json.loads(output.getvalue())
            self.assertEqual(exit_code, 4)
            self.assertGreater(payload["policy"]["new_unsuppressed_findings"], 0)
            self.assertEqual(payload["policy"]["blocking_findings"], 1)
            self.assertTrue((base / "results" / "policy.json").is_file())
            summary_path = base / "results" / "policy-summary.md"
            self.assertTrue(summary_path.is_file())
            self.assertIn("**FAIL**", summary_path.read_text(encoding="utf-8"))
            report_page = (base / "results" / "report" / "index.html").read_text(encoding="utf-8")
            report_manifest = json.loads(
                (base / "results" / "report" / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertIn("CI policy status", report_page)
            self.assertTrue(report_manifest["policy_embedded"])

    def test_category_and_confidence_filter_only_changes_blocking_decision(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            repository.mkdir()
            (repository / "agent.ts").write_text(
                "export function run(value: string) { return exec(value); }\n",
                encoding="utf-8",
            )
            result = analyze_repository(repository, base / "results")
            all_new = evaluate_policy(result.findings)
            high_only = evaluate_policy(
                result.findings,
                blocking_categories=("command_execution",),
                minimum_confidence="high",
            )
            self.assertEqual(all_new["new_unsuppressed_findings"], 1)
            self.assertEqual(all_new["blocking_findings"], 1)
            self.assertEqual(high_only["new_unsuppressed_findings"], 1)
            self.assertEqual(high_only["blocking_findings"], 0)
            self.assertIn("**PASS**", policy_markdown(high_only))


if __name__ == "__main__":
    unittest.main()
