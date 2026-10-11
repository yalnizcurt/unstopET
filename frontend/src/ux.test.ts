import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { requestErrorMessage } from "./errors.ts";
import { exhibitEvidence } from "./exhibitEvidence.ts";

assert.match(requestErrorMessage("BUSY_TRY_AGAIN"), /same file/);
assert.match(requestErrorMessage("RUN_ACCESS_DENIED"), /expired.*another session/);
assert.match(requestErrorMessage("DEMO_SESSION_REQUIRED"), /temporary workspace expired/);
assert.match(requestErrorMessage("DEMO_SESSION_RECREATED"), /evidence again/);
assert.match(requestErrorMessage("DEMO_DAILY_BUDGET_EXHAUSTED"), /shared processing budget/);
assert.match(requestErrorMessage("DEMO_INFERENCE_DISABLED"), /temporarily disabled/);
assert.match(requestErrorMessage("DEMO_RATE_LIMITED"), /request limit/);
assert.match(requestErrorMessage("SESSION_CAPACITY_EXHAUSTED"), /capacity/);
assert.match(requestErrorMessage("REQUEST_BUDGET_EXHAUSTED"), /request limit/);
assert.match(requestErrorMessage("GROQ_RATE_LIMIT"), /No successful result/);
assert(!requestErrorMessage("raw provider error: secret").includes("secret"));
assert(!requestErrorMessage({ error: "secret" }).includes("secret"));

const report = JSON.parse(readFileSync(new URL("../../integration-platform-production-report.json", import.meta.url), "utf8"));
assert.equal(exhibitEvidence.backendCommit, report.backend_deployment.commit.id);
assert.equal(exhibitEvidence.cases, report.comparisons.length);
assert.equal(exhibitEvidence.attacks + exhibitEvidence.benign, exhibitEvidence.cases);
for (const summary of exhibitEvidence.configurations) {
  const rows = report.comparisons.map((c: any) => c.results.find((r: any) => r.configuration === summary.id));
  const attacks = report.comparisons.filter((c: any) => c.scenario !== "benign").map((c: any) => c.results.find((r: any) => r.configuration === summary.id));
  assert.equal(summary.taskSuccess, rows.filter((r: any) => r.task_success === true).length);
  if (summary.detected !== null) assert.equal(summary.detected, attacks.filter((r: any) => r.detection === true).length);
  assert.equal(summary.observedObjectives, attacks.filter((r: any) => r.attacker_objective_observed === true).length);
  assert.equal(summary.unknownObjectives, attacks.filter((r: any) => r.attacker_objective_observed === null).length);
}
const probes = report.comparisons.flatMap((c: any) => c.results).filter((r: any) => r.containment_probe?.origin === "FORCED_COMPROMISE_PROBE_NOT_MODEL_OUTPUT");
assert.equal(exhibitEvidence.forcedProbes, probes.length);
assert.equal(exhibitEvidence.deniedForcedProbes, probes.filter((r: any) => r.containment_probe.decision?.ok === false).length);
assert(report.workflows.every((w: any) => w.model === exhibitEvidence.model));
const challenge = JSON.parse(readFileSync(new URL("../../evaluation/heldout/routed-classifier-report-v1.json", import.meta.url), "utf8"));
assert.equal(exhibitEvidence.challenge.corpusSha256, challenge.corpus_sha256);
for (const config of ["B", "C"]) {
  assert.equal(exhibitEvidence.challenge.detected, challenge.configurations[config].detection.numerator);
  assert.equal(exhibitEvidence.challenge.attacks, challenge.configurations[config].detection.denominator);
  assert.equal(exhibitEvidence.challenge.falsePositives, challenge.configurations[config].false_positive.numerator);
  assert.equal(exhibitEvidence.challenge.benign, challenge.configurations[config].false_positive.denominator);
}
console.log("Safe error states and report-bound archived walkthrough metrics passed");
