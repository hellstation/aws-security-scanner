import unittest

from awscan.main import should_fail


class FailOnTests(unittest.TestCase):
    def test_should_fail_returns_false_when_results_are_below_threshold(self):
        results = [{"severity": "MEDIUM"}, {"severity": "LOW"}]
        self.assertFalse(should_fail(results, "HIGH"))

    def test_should_fail_returns_true_when_threshold_is_hit(self):
        results = [{"severity": "HIGH"}]
        self.assertTrue(should_fail(results, "HIGH"))

    def test_should_fail_returns_true_when_threshold_is_exceeded(self):
        results = [{"severity": "CRITICAL"}]
        self.assertTrue(should_fail(results, "HIGH"))


if __name__ == "__main__":
    unittest.main()
