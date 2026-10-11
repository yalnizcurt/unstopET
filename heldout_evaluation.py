"""First-use challenge inspection; no generation, actions, detector tuning or benchmark replication."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path

from evaluation import SCENARIOS, fixture
from extractors import extract
from firewall import Denied
from inspection import inspect
from reliability_benchmark import ATTACKS, BENIGN, wilson
from semantic import GUARD_MODEL, PromptGuard

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "evaluation/heldout"
SECURITY_FILES = ("inspection.py", "extractors.py", "semantic.py", "firewall.py", "groq_ai.py")


def load_corpus():
    raw = (DATA / "corpus-v1.json").read_bytes()
    corpus = json.loads(raw)
    frozen = json.loads((DATA / "FREEZE.json").read_text())
    if hashlib.sha256(raw).hexdigest() != frozen["sha256"]:
        raise ValueError("CORPUS_CHANGED_AFTER_FREEZE")
    if len(corpus["cases"]) != frozen["case_count"]:
        raise ValueError("CORPUS_COUNT_MISMATCH")
    development = {x[-1].strip().casefold() for x in (*ATTACKS, *BENIGN)}
    development.update(x["attack"].strip().casefold() for x in SCENARIOS.values())
    for case in corpus["cases"]:
        if any(d["content"].strip().casefold() in development for d in case["documents"]):
            raise ValueError("EXACT_DEVELOPMENT_PAYLOAD_OVERLAP")
    return corpus, frozen


class ClassifierBudget:
    """Experiment-wide limits in addition to unchanged per-case production limits."""
    def __init__(self, provider, max_calls=128, max_seconds=180, max_tokens=16000):
        self.provider = provider
        self.max_calls, self.max_seconds, self.max_tokens = max_calls, max_seconds, max_tokens
        self.calls = self.tokens = 0
        self.seconds = 0.0
        self.errors = []

    def classifier(self):
        guard = PromptGuard(self.provider)

        def call(content):
            if self.calls >= self.max_calls or self.seconds >= self.max_seconds or self.tokens >= self.max_tokens:
                raise Denied("CLASSIFIER_STUDY_BUDGET_EXHAUSTED")
            before = guard.calls, guard.seconds, guard.tokens
            try:
                return guard(content)
            except Denied as error:
                self.errors.append(error.code)
                raise
            finally:
                self.calls += guard.calls - before[0]
                self.seconds += guard.seconds - before[1]
                self.tokens += guard.tokens - before[2]
        return call


def percentile(values, fraction):
    return round(sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)], 6) if values else None


def summarize(rows):
    attacks = [r for r in rows if r["label"] == "attack"]
    benign = [r for r in rows if r["label"] == "benign"]
    tp = sum(r["detected"] is True for r in attacks)
    fp = sum(r["detected"] is True for r in benign)
    fn = sum(r["detected"] is False for r in attacks)
    tn = sum(r["detected"] is False for r in benign)
    return dict(cases=len(rows), attacks=len(attacks), benign=len(benign),
        confusion_matrix=dict(TP=tp, FN=fn, FP=fp, TN=tn,
            attack_unknown=len(attacks)-tp-fn, benign_unknown=len(benign)-fp-tn),
        detection=dict(numerator=tp, denominator=len(attacks), rate=round(tp/len(attacks), 4) if attacks else None,
            descriptive_wilson_95=wilson(tp, len(attacks))),
        false_positive=dict(numerator=fp, denominator=len(benign), rate=round(fp/len(benign), 4) if benign else None,
            descriptive_wilson_95=wilson(fp, len(benign))),
        incomplete_cases=sum(r["coverage"] != "COMPLETE" for r in rows),
        review_cases=sum(r["requires_review"] for r in rows),
        parser_failed_cases=sum(r["parser_error"] is not None for r in rows),
        latency_seconds=dict(p50=percentile([r["seconds"] for r in rows], .5),
            p95=percentile([r["seconds"] for r in rows], .95), method="nearest rank; inspection only, parser time separate"),
        benign_preserved_cases=sum(r["label"] == "benign" and r["all_content_preserved"] for r in rows),
        unknown_agent_behavior=len(rows), unknown_attacker_objective=len(attacks),
        observed_external_executions=None, task_success=None)


def evaluate(provider=None):
    corpus, frozen = load_corpus()
    budget = ClassifierBudget(provider) if provider else None
    report = dict(schema_version=1, suite=corpus["version"], corpus_sha256=frozen["sha256"],
        created_at=datetime.now(timezone.utc).isoformat(),
        mode="DETERMINISTIC_AND_ROUTED_CLASSIFIER" if budget else "DETERMINISTIC_ONLY",
        classifier_model=GUARD_MODEL if budget else None,
        threshold=.9, detector_tuned_to_this_set=False,
        source_sha256={f: hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in SECURITY_FILES},
        scope="Offline static fragment inspection through existing extract/inspect adapters. No agent generation or executor experiment.",
        limitations=corpus["limitations"] + [
            "Public case attacker tools are descriptions only; no upstream tool or action is executed.",
            "Formats are a small convenience sample; image/OCR, audio/video and arbitrary binary channels are not measured.",
            "Direct offline parsing does not establish parser sandbox containment; use Linux acceptance evidence separately.",
            "Content preservation compares inspected fragment dispositions, not successful task completion.",
            "Scores are classifier outputs, not calibrated probabilities; confidence intervals are descriptive convenience-sample bounds.",
            "A multi-source case is scored detected if any fragment signals; there is no implemented temporal/cross-source attack correlator.",
            "This is not a full InjecAgent/AgentDojo/BIPIA evaluation or universal F3/D2 claim."], rows=[])
    for case in corpus["cases"]:
        trees = []
        parser_error = None
        start_parse = time.monotonic()
        try:
            for i, doc in enumerate(case["documents"]):
                if doc["surface"] == "text":
                    name, content = f"{case['id']}-{i}.txt", doc["content"].encode()
                else:
                    name, content = fixture(doc["surface"], doc["content"])
                trees.append(extract(name, content))
        except Exception as error:
            # Never serialize raw parser/provider errors; failed cases remain unknown.
            parser_error = type(error).__name__
        parse_seconds = round(time.monotonic()-start_parse, 6)
        for config in ("B", "C") if budget else ("B",):
            started = time.monotonic()
            classifier = budget.classifier() if config == "C" else None
            results = [inspect(tree, classifier) for tree in trees] if not parser_error else []
            fragments = [f for r in results for f in r["fragments"]]
            signals = [s for f in fragments for s in f["signals"]]
            review = any(f["disposition"] == "REQUIRE_REVIEW" for f in fragments)
            gaps = [g for r in results for g in r["uninspected_channels"]]
            row = dict(case_id=case["id"], configuration=config, label=case["label"],
                family=case["family"], provenance=case["provenance"],
                surfaces=[d["surface"] for d in case["documents"]], documents=len(case["documents"]),
                detected=True if signals else None if parser_error or review else False,
                requires_review=review, parser_error=parser_error,
                coverage="FAILED" if parser_error else "PARTIAL" if gaps else "COMPLETE",
                uninspected_channels=gaps, released_scopes=[r["release_scope"] for r in results],
                all_content_preserved=bool(fragments) and all(f["disposition"] == "ALLOW" for f in fragments),
                signals=signals, semantic_routed_fragments=sum(f["router"] == "SEMANTIC_REQUIRED" for f in fragments),
                skipped_semantic_reasons=sorted({f["routing"]["reason"] for f in fragments if f["router"] != "SEMANTIC_REQUIRED"}),
                seconds=round(time.monotonic()-started, 6), parser_seconds=parse_seconds,
                behavior="NOT_MEASURED", attacker_objective="NOT_MEASURED", executor_enforcement="NOT_MEASURED")
            report["rows"].append(row)
    report["configurations"] = {}
    for config in ("B", "C") if budget else ("B",):
        rows = [r for r in report["rows"] if r["configuration"] == config]
        report["configurations"][config] = summarize(rows)
        report["configurations"][config]["by_provenance"] = {p: summarize([r for r in rows if r["provenance"] == p]) for p in sorted({r["provenance"] for r in rows})}
        report["configurations"][config]["by_family"] = {p: summarize([r for r in rows if r["family"] == p]) for p in sorted({r["family"] for r in rows})}
        report["configurations"][config]["by_surface"] = {p: summarize([r for r in rows if p in r["surfaces"]]) for p in sorted({s for r in rows for s in r["surfaces"]})}
    report["classifier_budget"] = dict(calls=budget.calls, tokens=budget.tokens, seconds=round(budget.seconds, 3), errors=budget.errors,
        max_calls=budget.max_calls, max_seconds=budget.max_seconds, max_tokens=budget.max_tokens, cost_usd=None) if budget else None
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    Path(args.output).write_text(json.dumps(evaluate(), indent=2)+"\n")


if __name__ == "__main__":
    main()
