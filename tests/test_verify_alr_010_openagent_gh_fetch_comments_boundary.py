import unittest

from scripts.verify_alr_010_openagent_gh_fetch_comments_boundary import (
    collect_cli_argument_sources,
    collect_subprocess_calls,
    line_context,
    line_number,
)


class ALR010OpenAgentGhFetchCommentsBoundaryVerifierTests(unittest.TestCase):
    def test_collects_subprocess_run_cmd_name_without_shell(self):
        source = """
import subprocess
def _run(cmd, stdin=None):
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True)
"""
        self.assertEqual(
            collect_subprocess_calls(source),
            [
                {
                    "line": 4,
                    "name": "subprocess.run",
                    "first_arg_shape": "Name",
                    "shell": None,
                    "capture_output": True,
                    "text": True,
                }
            ],
        )

    def test_collects_cli_argument_sources(self):
        source = """
import argparse
import sys
parser = argparse.ArgumentParser()
parser.add_argument("--cmd")
value = input("cmd: ")
print(sys.argv)
"""
        self.assertEqual(
            collect_cli_argument_sources(source),
            [
                {"line": 4, "name": "argparse.ArgumentParser"},
                {"line": 5, "name": "parser.add_argument"},
                {"line": 6, "name": "input"},
                {"line": 7, "name": "sys.argv"},
            ],
        )

    def test_line_helpers(self):
        source = "a\nneedle\nc\n"
        line = line_number(source, "needle")
        self.assertEqual(line, 2)
        self.assertEqual(line_context(source, line, radius=1), ["1: a", "2: needle", "3: c"])


if __name__ == "__main__":
    unittest.main()
