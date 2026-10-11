"""Regression checks for the separate offline, non-model reliability suite."""
import unittest

from reliability_benchmark import ATTACKS, BENIGN, SURFACES, evaluate, wilson


class ReliabilityBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = evaluate()

    def test_all_cases_have_complete_confusion_accounting(self):
        r = self.result
        self.assertEqual(r["cases"], (len(ATTACKS) + len(BENIGN)) * len(SURFACES))
        confusion = r["confusion_matrix"]
        self.assertEqual(sum(confusion.values()), r["cases"])
        self.assertEqual(confusion["TP"] + confusion["FN"], len(ATTACKS) * len(SURFACES))
        self.assertEqual(confusion["FP"] + confusion["TN"], len(BENIGN) * len(SURFACES))
        self.assertEqual(len(r["cases_detail"]), r["cases"])

    def test_unknowns_and_misses_are_reported_not_hidden(self):
        r = self.result
        self.assertIn("FN", r["confusion_matrix"])
        self.assertIn("FP", r["confusion_matrix"])
        self.assertIn("incomplete_inspections", r)
        self.assertTrue(all("incomplete" in v for v in r["by_surface"].values()))
        self.assertTrue(all("detected" in v for v in r["categories"].values()))
        self.assertFalse(any("certified" in r.get("scope", "").lower() for _ in [0]))

    def test_all_cases_are_declared_and_coverage_counts_are_consistent(self):
        r = self.result
        self.assertEqual(r["distinct_authored_payloads"], len(ATTACKS) + len(BENIGN))
        self.assertEqual(sum(x["cases"] for x in r["categories"].values()), len(ATTACKS)*len(SURFACES))
        self.assertTrue(all(x["cases"] == len(ATTACKS)+len(BENIGN) for x in r["by_surface"].values()))
        self.assertTrue(all(row["inspection_status"] in ("COMPLETE","PARTIAL","UNSUPPORTED","FAILED")
                            for row in r["cases_detail"]))

    def test_interval_boundary_behavior(self):
        self.assertIsNone(wilson(0, 0))
        self.assertEqual(wilson(0, 10)[0], 0.0)
        self.assertEqual(wilson(10, 10)[1], 1.0)


if __name__ == "__main__":
    unittest.main()
