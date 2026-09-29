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

from agentsecbench import analyze_repository  # noqa: E402
from agentsecbench.cli import main  # noqa: E402
from agentsecbench.policy import evaluate_policy, write_policy_report  # noqa: E402
from agentsecbench.schemas import SCHEMA_NAMES, read_schema  # noqa: E402


SOURCE = """\
import subprocess

def run(command: str):
    return subprocess.run(command, shell=True)
"""


class ProductSchemaTests(unittest.TestCase):
    def test_all_public_schemas_are_bundled_and_versioned(self) -> None:
        self.assertEqual(len(SCHEMA_NAMES), 6)
        for name in SCHEMA_NAMES:
            schema = read_schema(name)
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertIn(f"/{name}.schema.json", schema["$id"])
            self.assertEqual(schema["type"], "object")
            self.assertTrue(schema["required"])

    def test_emitted_records_satisfy_published_top_level_contracts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repo"
            repository.mkdir()
            (repository / "agent.py").write_text(SOURCE, encoding="utf-8")
            result = analyze_repository(repository, base / "out")
            policy = evaluate_policy(result.findings)
            write_policy_report(base / "out" / "policy.json", policy)
            records = {
                "finding": result.findings[0].to_dict(),
                "security-adg": result.graphs[0],
                "summary": result.summary.to_dict(),
                "policy": policy,
                "report-manifest": json.loads((base / "out" / "report" / "manifest.json").read_text(encoding="utf-8")),
            }
            for name, record in records.items():
                schema = read_schema(name)
                self.assertFalse(set(schema["required"]) - set(record), name)
                self.assertEqual(record["schema_version"], schema["properties"]["schema_version"]["const"])

    def test_schema_cli_lists_and_prints_without_network(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["schema", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue())["schema_names"], list(SCHEMA_NAMES))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["schema", "finding"]), 0)
        self.assertEqual(json.loads(output.getvalue())["title"], "AgentSecBench finding")


if __name__ == "__main__":
    unittest.main()
