"""Accounting and freeze checks; no network/model calls in regression tests."""
import unittest
from unittest.mock import patch

from firewall import Denied
from heldout_evaluation import ClassifierBudget, evaluate, load_corpus, percentile, summarize


class HeldOutEvaluationTests(unittest.TestCase):
    def test_frozen_corpus_and_source_boundaries(self):
        corpus, frozen = load_corpus()
        self.assertEqual(len(corpus["cases"]), frozen["case_count"])
        self.assertFalse(frozen["detector_tuned_to_this_set"])
        self.assertEqual(len({c["id"] for c in corpus["cases"]}), 64)
        public = [c for c in corpus["cases"] if c["provenance"] == "PUBLIC_BENCHMARK_FIRST_USE"]
        self.assertEqual(len(public), 32)
        self.assertTrue(all(c["source"]["license"] == "MIT" for c in public))
        self.assertEqual(len({c["upstream_instruction"] for c in public}), 32)

    def test_all_cases_scored_without_hiding_misses(self):
        report = evaluate()
        result = report["configurations"]["B"]
        self.assertEqual(len(report["rows"]), 64)
        self.assertEqual((result["attacks"], result["benign"]), (48, 16))
        self.assertEqual(sum(result["confusion_matrix"].values()), 64)
        self.assertIsNone(result["task_success"])
        self.assertEqual(result["unknown_agent_behavior"], 64)
        self.assertEqual(result["unknown_attacker_objective"], 48)
        self.assertTrue(all(r["behavior"] == "NOT_MEASURED" for r in report["rows"]))
        self.assertTrue(all("uninspected_channels" in r for r in report["rows"]))
        self.assertNotIn("C", report["configurations"])

    def test_unknown_not_counted_as_true_negative(self):
        row = dict(label="benign", detected=None, coverage="PARTIAL", requires_review=True,
            parser_error=None, seconds=0.0, all_content_preserved=False)
        result = summarize([row])
        self.assertEqual(result["confusion_matrix"]["TN"], 0)
        self.assertEqual(result["confusion_matrix"]["benign_unknown"], 1)
        self.assertEqual(result["review_cases"], 1)
        self.assertIsNone(percentile([], .95))
        self.assertEqual(percentile([1., 2., 3.], .95), 3.0)

    def test_study_budget_stops_before_another_provider_call(self):
        class Guard:
            def __init__(self, provider):
                self.calls = self.tokens = 0
                self.seconds = 0.0
            def __call__(self, content):
                self.calls += 1
                self.tokens += 10
                self.seconds += .01
                return .8
        with patch("heldout_evaluation.PromptGuard", Guard):
            budget = ClassifierBudget(object(), max_calls=1)
            classifier = budget.classifier()
            self.assertEqual(classifier("synthetic evidence"), .8)
            with self.assertRaises(Denied) as error:
                classifier("a second request")
            self.assertEqual(error.exception.code, "CLASSIFIER_STUDY_BUDGET_EXHAUSTED")
            self.assertEqual((budget.calls, budget.tokens), (1, 10))


if __name__ == "__main__":
    unittest.main()
