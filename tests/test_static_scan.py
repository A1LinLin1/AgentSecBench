from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from static_scan import RULES, detector_applies_to_suffix, python_dynamic_operation_lines  # noqa: E402


class DetectorLanguageScopeTests(unittest.TestCase):
    def test_python_detector_does_not_apply_to_go_or_java(self):
        self.assertTrue(detector_applies_to_suffix("py_eval_exec", ".py"))
        self.assertFalse(detector_applies_to_suffix("py_eval_exec", ".go"))
        self.assertFalse(detector_applies_to_suffix("py_eval_exec", ".java"))

    def test_javascript_detector_supports_typescript_family(self):
        self.assertTrue(detector_applies_to_suffix("js_eval_function", ".ts"))
        self.assertTrue(detector_applies_to_suffix("js_eval_function", ".tsx"))
        self.assertFalse(detector_applies_to_suffix("js_eval_function", ".py"))

    def test_language_independent_detector_remains_available(self):
        self.assertTrue(detector_applies_to_suffix("browser_framework", ".py"))
        self.assertTrue(detector_applies_to_suffix("browser_framework", ".ts"))

    def test_dynamic_execution_rule_excludes_function_declarations(self):
        pattern = next(rule.pattern for rule in RULES if rule.detector == "py_eval_exec")
        self.assertFalse(pattern.search("def exec(code: str):"))
        self.assertFalse(pattern.search("async def eval(expression):"))
        self.assertTrue(pattern.search("result = eval(expression)"))

    def test_python_ast_dynamic_operation_filter_rejects_prose(self):
        source = '''\
# exec(payload)
def exec(payload):
    note = "eval(expression)"
    return compile(payload, "<input>", "exec")
'''
        self.assertEqual(python_dynamic_operation_lines(source), {4})

    def test_agent_framework_tool_definition_rules_are_present(self):
        detectors = {rule.detector: rule for rule in RULES}
        samples = {
            "langchain_tool_definition": "@tool\ndef shell(command: str): pass",
            "crewai_tool_definition": "class ShellTool(BaseTool):\n    pass",
            "autogen_tool_registration": "assistant.register_for_llm()(run_code)",
            "openai_agents_tool_definition": "@function_tool\ndef write_file(path: str): pass",
            "semantic_kernel_tool_definition": "@kernel_function\ndef fetch(url: str): pass",
            "llamaindex_tool_definition": "tool = FunctionTool.from_defaults(fn=read_file)",
        }
        for detector, sample in samples.items():
            with self.subTest(detector=detector):
                self.assertIn(detector, detectors)
                self.assertRegex(sample, detectors[detector].pattern)


if __name__ == "__main__":
    unittest.main()
