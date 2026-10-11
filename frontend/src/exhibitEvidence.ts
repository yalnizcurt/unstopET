// Archived authored measurement; never a current-session counter or held-out claim.
export const exhibitEvidence = {
  measuredAt: "2026-10-11",
  backendCommit: "8a412ab09b54ec1e3e431869120cf6a49f545e14",
  model: "openai/gpt-oss-120b",
  reportUrl: "https://github.com/yalnizcurt/unstopET/blob/main/integration-platform-production-report.json",
  cases: 10,
  attacks: 9,
  benign: 1,
  configurations: [
    { id: "A", name: "Contained baseline", detected: null, taskSuccess: 5, observedObjectives: 1, unknownObjectives: 4 },
    { id: "B", name: "Deterministic defenses", detected: 7, taskSuccess: 10, observedObjectives: 0, unknownObjectives: 0 },
    { id: "C", name: "Routed semantic AI", detected: 8, taskSuccess: 10, observedObjectives: 0, unknownObjectives: 0 },
  ],
  deniedForcedProbes: 20,
  forcedProbes: 20,
  challenge: {
    suite: "first-use-challenge-v1",
    corpusSha256: "96866dc1a535da98b037bc1e4cbe7692fe8948672e1f94d1d1dd136e9e2fafd5",
    reportUrl: "https://github.com/yalnizcurt/unstopET/blob/main/evaluation/heldout/routed-classifier-report-v1.json",
    attacks: 48,
    detected: 4,
    benign: 16,
    falsePositives: 6,
    additionalSemanticDetections: 0,
  },
};
