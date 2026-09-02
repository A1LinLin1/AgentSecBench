from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_security_adg_showcase.py"
FIXTURE = ROOT / "tests" / "fixtures" / "security_adg_showcase.jsonl"


class SecurityAdgShowcaseTests(unittest.TestCase):
    def test_standalone_page_and_manifest_are_generated(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "showcase"
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--graphs", str(FIXTURE), "--output-dir", str(output), "--max-graphs", "2"],
                check=True, capture_output=True, text=True,
            )
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            page = (output / "index.html").read_text(encoding="utf-8")
            self.assertIn('"candidate_count": 2', completed.stdout)
            self.assertEqual(manifest["candidate_count"], 2)
            self.assertIn("FIX-SADG-001", page)
            self.assertIn("Static candidate", page)
            self.assertIn("Security-ADG", page)

    def test_explicit_candidate_selection_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "showcase"
            subprocess.run(
                [sys.executable, str(SCRIPT), "--graphs", str(FIXTURE), "--output-dir", str(output), "--candidate-id", "FIX-SADG-002"],
                check=True, capture_output=True, text=True,
            )
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual([item["candidate_id"] for item in manifest["candidates"]], ["FIX-SADG-002"])


if __name__ == "__main__":
    unittest.main()
