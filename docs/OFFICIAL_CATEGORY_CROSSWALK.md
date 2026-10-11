# Attack category crosswalk

The names below match the nine-category taxonomy supplied in the original user problem statement, section 27. The original official branded PDF is not available in this checkout. This is a traceable engineering crosswalk, not official F3/D2 certification. Seven separately authored category fixtures have measured detection, task and contained-effect outcomes; format repetitions do not add categories.

| Requirement label | Fixture / detector | Measured evidence | Remaining gap |
|---|---|---|---|
| Instruction Override | override / Deterministic; routed Prompt Guard when selected | b6bc04b8e505009ef2e329a8ae54ce63 | Authored small sample; no independent unseen-family reliability |
| Role Change | role / Deterministic; routed Prompt Guard when selected | 09d8fe4811abee19ed382b7c6355b52a | Authored small sample; no independent unseen-family reliability |
| Secret Extraction | secret / Deterministic; routed Prompt Guard when selected | dc21fcc438b0808997c957517a63a248 | Authored small sample; no independent unseen-family reliability |
| Tool Abuse | tool / Deterministic; routed Prompt Guard when selected | f6ae465ca18d06b4cebffe2ec8909238 | Authored small sample; no independent unseen-family reliability |
| Credential Theft | credential / Deterministic; routed Prompt Guard when selected | 87d927460c47729e977f6d25b7eb1b73 | Authored small sample; no independent unseen-family reliability |
| Context Poisoning | Not implemented / No category claim | Not demonstrated | Persistent memory and broad cross-turn/source attack correlation are disabled; no category detection claim |
| Multi-Step Jailbreaks | Not implemented / No category claim | Not demonstrated | Persistent memory and broad cross-turn/source attack correlation are disabled; no category detection claim |
| Encoded Instructions | encoded / Deterministic; routed Prompt Guard when selected | 0f4901521b969540fd723bf37b7579a5 | Authored small sample; no independent unseen-family reliability |
| Indirect Prompt Injection | indirect / Deterministic; routed Prompt Guard when selected | 15d10868c6891d1b19073e522bdf2a71 | Authored small sample; no independent unseen-family reliability |

Full category/configuration outcomes, surfaces, timestamps and source commits: [official-category-crosswalk.json](../official-category-crosswalk.json). Original outputs and decisions remain in [cloud-evaluation-report.json](../cloud-evaluation-report.json). New production comparisons are reported separately; historical measurements are not presented as runs on new source. Runtime multi-step capability is not proof of multi-step jailbreak detection.
