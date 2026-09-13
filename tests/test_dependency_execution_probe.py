import unittest

from scripts.run_dependency_execution_probe import oracle, source_for, counts


class ExecutionOracleTests(unittest.TestCase):
    def test_parameter_and_literal_controls(self):
        self.assertTrue(oracle(source_for("return subprocess.run(command)"))["label"])
        self.assertFalse(oracle(source_for('return subprocess.run("fixed")'))["label"])

    def test_copy_before_overwrite_preserves_runtime_value(self):
        result = oracle(source_for('saved = command\ncommand = "fixed"\nreturn subprocess.run(saved)'))
        self.assertTrue(result["label"])
        self.assertEqual(result["observations"][0]["trace"][0]["args"], ["ASB_A"])

    def test_unreached_operation_is_not_negative(self):
        self.assertIsNone(oracle(source_for("return None"))["label"])

    def test_inconclusive_is_not_silently_scored(self):
        rows = [{"oracle": {"label": None}, "predictions": {"m": {"prediction": False}}}]
        self.assertEqual(counts(rows, "m")["support"], 0)
        self.assertIsNone(counts(rows, "m")["f1"])


if __name__ == "__main__":
    unittest.main()
