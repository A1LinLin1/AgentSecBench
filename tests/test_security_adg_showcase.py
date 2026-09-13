from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_security_adg_showcase.py"
FIXTURE = ROOT / "tests" / "fixtures" / "security_adg_showcase.jsonl"
sys.path.insert(0, str(ROOT / "scripts"))
from generate_security_adg_showcase import compact_graph, page_html
from security_adg_figure import VIEWS, figure_svg
from build_agent_case_study_showcase_graphs import alr_001_graph, alr_003_graph, alr_007_graph, ase_0007_graph


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
            self.assertEqual(len(manifest["files"]["figures"]), 6)
            for filename in manifest["files"]["figures"]:
                ET.parse(output / filename)

    def test_explicit_candidate_selection_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "showcase"
            subprocess.run(
                [sys.executable, str(SCRIPT), "--graphs", str(FIXTURE), "--output-dir", str(output), "--candidate-id", "FIX-SADG-002"],
                check=True, capture_output=True, text=True,
            )
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual([item["candidate_id"] for item in manifest["candidates"]], ["FIX-SADG-002"])

    def test_case_figures_preserve_graph_and_avoid_node_collisions(self):
        for graph in [alr_001_graph(), alr_003_graph(), alr_007_graph(), ase_0007_graph()]:
            case = compact_graph(graph)
            for view in VIEWS:
                with self.subTest(case=case["candidateId"], view=view):
                    svg, plan = figure_svg(case, view)
                    root = ET.fromstring(svg)
                    self.assertEqual(svg, figure_svg(case, view)[0])
                    self.assertEqual({n.attrib["data-id"] for n in root.iter() if "data-id" in n.attrib}, set(case["views"][view]["nodes"]))
                    expected_edges = [e for e in case["edges"] if e["from"] in plan["boxes"] and e["to"] in plan["boxes"] and e["type"] in case["views"][view]["edges"]]
                    self.assertEqual(len(plan["routes"]), len(expected_edges))
                    boxes = list(plan["boxes"].values())
                    for i, a in enumerate(boxes):
                        self.assertGreaterEqual(a["x"], 0)
                        self.assertLessEqual(a["x"]+a["width"],plan["width"])
                        self.assertLessEqual(a["y"]+a["height"],plan["height"]-80)
                        for b in boxes[i+1:]:
                            self.assertFalse(a["x"]<b["x"]+b["width"] and b["x"]<a["x"]+a["width"] and a["y"]<b["y"]+b["height"] and b["y"]<a["y"]+a["height"])
                    for route in plan["routes"]:
                        for p,q in zip(route["points"],route["points"][1:]):
                            for nid,b in plan["boxes"].items():
                                if nid in (route["from"],route["to"]): continue
                                x1,x2=sorted((p[0],q[0]));y1,y2=sorted((p[1],q[1]))
                                if x1==x2:
                                    collision=b["x"]<x1<b["x"]+b["width"] and y1<b["y"]+b["height"] and y2>b["y"]
                                else:
                                    collision=b["y"]<y1<b["y"]+b["height"] and x1<b["x"]+b["width"] and x2>b["x"]
                                self.assertFalse(collision, (case["candidateId"], route, nid))

    def test_labels_are_escaped_and_not_truncated(self):
        case = compact_graph(alr_007_graph())
        label = '</script><script>alert("x")</script>' + 'long_symbol_' * 12
        case["nodes"][0]["label"] = label
        svg, plan = figure_svg(case, "security_adg")
        self.assertEqual(''.join(plan["boxes"]["n1"]["lines"]), label)
        ET.fromstring(svg)
        self.assertNotIn('</script>', svg)
        page = page_html([case], 'fixture.jsonl')
        self.assertEqual(page.count('</script>'), 1)


if __name__ == "__main__":
    unittest.main()
