import ast
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.mine_dependency_challenge_cases import RepoRow, find_records


REPO = RepoRow("ASBT", "owner/repo", Path("."), "deadbeef")


def records(source: str):
    return find_records(REPO, "example.py", source, radius=1)[0]


class DependencyChallengeMiningTests(unittest.TestCase):
    def test_copy_before_overwrite_pattern(self):
        source = """
def tool(command):
    saved = command
    command = "fixed"
    return subprocess.run(saved)
"""
        found = records(source)
        self.assertEqual([row["mechanism"] for row in found], ["copy_before_overwrite"])
        self.assertFalse(found[0]["engine_current_worktree_v2_4_flags"]["prediction"])

    def test_conditional_overwrite_pattern(self):
        source = """
def tool(command):
    if command == "A":
        command = "fixed"
    return subprocess.run(command)
"""
        found = records(source)
        self.assertEqual([row["mechanism"] for row in found], ["conditional_parameter_overwrite"])
        self.assertEqual(found[0]["details"]["overwrites"][0]["parameter"], "command")

    def test_field_insensitive_container_pattern(self):
        source = """
def tool(command):
    payloads = {"ignored": command, "selected": "fixed"}
    return subprocess.run(payloads["selected"])
"""
        found = records(source)
        self.assertEqual([row["mechanism"] for row in found], ["field_insensitive_container"])
        self.assertTrue(found[0]["engine_current_worktree_v2_4_flags"]["prediction"])

    def test_does_not_flag_direct_parameter(self):
        source = """
def tool(command):
    return subprocess.run(command)
"""
        self.assertEqual(records(source), [])

    def test_does_not_flag_selected_parameter_dict_value(self):
        source = """
def tool(command):
    payloads = {"selected": command, "other": "fixed"}
    return subprocess.run(payloads["selected"])
"""
        self.assertEqual(records(source), [])

    def test_syntax_error_is_reported_not_raised(self):
        found, error = find_records(REPO, "bad.py", "def broken(:\n", radius=1)
        self.assertEqual(found, [])
        self.assertTrue(error.startswith("parse_error:"))


if __name__ == "__main__":
    unittest.main()
