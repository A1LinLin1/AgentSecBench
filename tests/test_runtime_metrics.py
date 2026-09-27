from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime_metrics import process_peak_rss_bytes  # noqa: E402


class RuntimeMetricsTests(unittest.TestCase):
    def test_peak_rss_is_positive_when_supported(self):
        value = process_peak_rss_bytes()
        if value is not None:
            self.assertGreater(value, 0)


if __name__ == "__main__":
    unittest.main()
