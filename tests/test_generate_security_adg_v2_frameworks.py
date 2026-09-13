from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from generate_security_adg_v2 import replace_heuristics  # noqa: E402
from security_adg_dataflow import analyze_python  # noqa: E402


class SecurityAdgV2FrameworkGraphTests(unittest.TestCase):
    def test_framework_evidence_updates_symbol_and_view(self):
        graph = {
            "nodes": [
                {"id": "n1", "type": "agent_or_program_symbol", "name": "shell", "agent_relevance": "unknown_pending_annotation"},
                {"id": "n2", "type": "security_sensitive_operation", "name": "subprocess.run", "category": "command_execution"},
                {"id": "n3", "type": "external_effect", "target_class": "process_or_shell"},
                {"id": "n4", "type": "trust_boundary", "boundary": "less_trusted_input_to_security_sensitive_effect"},
            ],
            "edges": [
                {"from": "n1", "to": "n2", "type": "contains"},
                {"from": "n2", "to": "n3", "type": "may_cause"},
                {"from": "n4", "to": "n2", "type": "reaches"},
            ],
            "views": {"security_adg": {}},
        }
        source = """\
from langchain.tools import Tool
import subprocess
def shell(command: str):
    return subprocess.run(command)
tool = Tool(name="shell", func=shell)
"""
        analysis = analyze_python(source, [4], symbol="shell")
        updated = replace_heuristics(graph, analysis, "test_generator")
        symbol = next(node for node in updated["nodes"] if node["type"] == "agent_or_program_symbol")
        source_node = next(node for node in updated["nodes"] if node["type"] == "input_source")
        self.assertEqual(symbol["agent_relevance"], "framework_confirmed")
        self.assertEqual(symbol["frameworks"], ["LangChain"])
        self.assertEqual(source_node["framework"], "LangChain")
        self.assertEqual(updated["views"]["security_adg"]["frameworks"], ["LangChain"])


if __name__ == "__main__":
    unittest.main()
