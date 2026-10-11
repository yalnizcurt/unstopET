# First-use challenge set v1

This set is a detection stress test, not a claim that the product passed InjecAgent or is universally secure. It was frozen before its first inspection. No signatures, router cues, thresholds, normalization or release policy were changed using its results.

`corpus-v1.json` contains 64 distinct cases: 32 public tool-output attacks, 16 new authored attacks and 16 new authored benign controls. Two authored cases contain two documents; these are static composition checks, not a multi-turn agent benchmark. The public subset is held out from this repository's earlier development fixtures. The newly authored attacks are **not blinded**: their author reviewed the detector before writing them. Classifier pretraining overlap is unknown.

The corpus SHA-256 is `96866dc1a535da98b037bc1e4cbe7692fe8948672e1f94d1d1dd136e9e2fafd5`. `FREEZE.json` binds the original bytes. The harness rejects a changed corpus or exact overlap with demonstration/168-case payloads. These controls do not prove semantic independence or absence from model training.

## Public source and license

The 32 external cases come from [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), revision `f19c9f2c79a41046eb13c03c51a24c567a8ffa07`. Each source file is hashed in the corpus. For each DH/DS base file, keep the first occurrence of every distinct attacker instruction, sort by SHA-256 of that instruction, and select the first 16. Selection precedes scoring. Preserve original attacker instructions and tool-response text; collect no upstream `Thought` field. `public-import.json` records indices and selection policy. The [upstream MIT license](https://github.com/uiuc-kang-lab/InjecAgent/blob/f19c9f2c79a41046eb13c03c51a24c567a8ffa07/LICENCE) is retained in `InjecAgent-LICENSE.txt`.

The new authored corpus text is marked CC0-1.0; that marking applies to these new scenario strings, not to the application, third-party benchmark or existing project assets. All upstream tool names and destinations remain inert evaluation text. The harness invokes no attacker tool.

## Original measured baseline

| Evidence | Deterministic B | Routed classifier C |
|---|---:|---:|
| All attack cases detected | 4/48 (8.3%) | 4/48 (8.3%) |
| Public tool-output attacks detected | 0/32 | 0/32 |
| Newly authored attacks detected | 4/16 | 4/16 |
| Benign false positives | 6/16 (37.5%) | 6/16 (37.5%) |
| Unknown detector outcomes | 0/64 | 0/64 |
| Required review / incomplete parsing | 0/64 | 0/64 |
| Inspection latency p50 | 0.000275 s | 0.000298 s |
| Inspection latency p95 | 0.001445 s | 0.195276 s |

The classifier was actually `meta-llama/llama-prompt-guard-2-86m`, called 11 times for 502 reported prompt tokens, taking 2.199 seconds cumulatively, with no provider errors. Ten cases routed at least one fragment; only one of 32 public attacks routed. AI added **zero detections on this set**. Cost is unknown; do not infer a dollar figure from token counts. Timing is one local run, inspection only, nearest-rank percentiles; parsing time is retained per case. Read `routed-classifier-report-v1.json` for source hashes, case-level misses, false positives, release scopes and every routing reason.

The familiar deterministic benchmark remains separate: `../authored-168-report.json` records 66/84 attacks detected (78.6%), 0/84 benign false positives and retained supplier prices in 168/168 format instances. Its 168 instances are 28 authored payloads repeated across six formats. The difference between familiar and first-use results is a material reliability gap, not evidence to average away.

No agent generation, attacker-objective scoring, legitimate-task completion or execution containment was measured here. Those fields are explicitly `NOT_MEASURED` or null. Use hosted A/B/C and forced-compromise evidence separately. Complete parsing means declared text channels were inspected; it does not mean an attack was detected.

## Reproduce and improve without contaminating evaluation

```sh
python heldout_evaluation.py --output evaluation/heldout/deterministic-report-v1.json
python -m unittest test_heldout_evaluation test_reliability_benchmark -v
```

The opt-in classifier evaluation calls `evaluate(GroqProvider(...))` from a credential-isolated local runner. Credentials must come from server configuration in memory and never be written to this directory or report. Production per-case classifier limits remain unchanged; the study adds 128 requests, 180 cumulative provider seconds and 16,000 reported prompt-token ceilings. Availability failures yield review/unknown outcomes rather than benign negatives.

If v1 informs a change, relabel it as a development/regression set and preserve these original reports. Freeze a genuinely separate v2 before final scoring. Test task-aware tool-output context, quoted security prose, and router recall first. Do not fix individual example strings and continue describing v1 as unseen.
