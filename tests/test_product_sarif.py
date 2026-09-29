from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from agentsecbench import __version__, analyze_repository, build_sarif  # noqa: E402


class ProductSarifTests(unittest.TestCase):
    def test_sarif_is_deterministic_and_matches_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repo"
            repository.mkdir()
            (repository / "agent.py").write_text(
                "import subprocess\ndef run(command):\n    return subprocess.run(command)\n",
                encoding="utf-8",
            )
            result = analyze_repository(repository, base / "output")
            sarif = json.loads(Path(result.summary.sarif_file).read_text(encoding="utf-8"))
            self.assertEqual(sarif, build_sarif(result.findings, __version__))
            self.assertEqual(sarif["version"], "2.1.0")
            run = sarif["runs"][0]
            self.assertEqual(len(run["results"]), result.summary.candidate_count)
            self.assertEqual(run["tool"]["driver"]["version"], __version__)
            self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "agent.py")
            self.assertIn("not a vulnerability claim", run["results"][0]["properties"]["claimBoundary"])
            self.assertEqual(run["results"][0]["partialFingerprints"]["agentsecbenchFindingId/v1"], result.findings[0].finding_id)
            self.assertEqual(
                run["results"][0]["partialFingerprints"]["agentsecbenchStableFingerprint/v1"],
                result.findings[0].fingerprint,
            )

    def test_empty_sarif_remains_valid_container(self) -> None:
        sarif = build_sarif((), __version__)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"], [])
        self.assertEqual(sarif["runs"][0]["results"], [])


if __name__ == "__main__":
    unittest.main()
