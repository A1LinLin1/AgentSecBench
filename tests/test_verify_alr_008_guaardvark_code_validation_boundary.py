import unittest

from scripts.verify_alr_008_guaardvark_code_validation_boundary import (
    collect_exec_family_calls,
    function_source,
    line_context,
    line_number,
)


class ALR008GuaardvarkCodeValidationBoundaryVerifierTests(unittest.TestCase):
    def test_collects_compile_exec_eval_family_calls(self):
        source = """
code = "x = 1"
compile(code, "<string>", "exec")
exec(code)
eval("1 + 1")
"""
        self.assertEqual(
            collect_exec_family_calls(source),
            [
                {"line": 3, "name": "compile", "arg0_shape": "Name", "mode": "exec"},
                {"line": 4, "name": "exec", "arg0_shape": "Name", "mode": None},
                {"line": 5, "name": "eval", "arg0_shape": "1 + 1", "mode": None},
            ],
        )

    def test_extracts_function_source(self):
        source = """
def a():
    return 1

def _execute_validate():
    compile("x=1", "<string>", "exec")
    return 2

def b():
    return 3
"""
        extracted = function_source(source, "_execute_validate")
        self.assertIn("def _execute_validate():", extracted)
        self.assertIn('compile("x=1", "<string>", "exec")', extracted)
        self.assertNotIn("def b():", extracted)

    def test_line_helpers(self):
        source = "a\nneedle\nc\n"
        line = line_number(source, "needle")
        self.assertEqual(line, 2)
        self.assertEqual(line_context(source, line, radius=1), ["1: a", "2: needle", "3: c"])


if __name__ == "__main__":
    unittest.main()
