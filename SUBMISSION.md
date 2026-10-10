# Agent Trust Firewall — hackathon submission package

## Product

Agent Trust Firewall is a working AI agent security platform for teams integrating AI with documents, websites and developer workflows. Prompt injection can make external information appear authoritative; detecting a suspicious phrase alone cannot constrain the resulting operation. The platform combines shared evidence inspection, server-controlled context assembly and mandatory execution/disclosure checks with a specialist semantic detector.

The differentiator is measurable defense in depth: the same enforcement boundaries protect three distinct agents and continue denying unauthorized operations even in an explicitly forced compromise experiment. Useful inspected facts remain available so authorized work can continue. Every enabled dashboard, investigation and evaluation displays actual stored results.

## Application links

- Console: https://agent-trust-firewall.vercel.app
- API: https://agent-trust-firewall-api.onrender.com
- API reference: https://agent-trust-firewall-api.onrender.com/api/docs
- Repository: https://github.com/yalnizcurt/unstopET

Use the server-configured demo access code, never the Groq key. No submission portal upload or official assessment is claimed.

## Working agents and security

| Agent | Actual business workflow | Shared protection |
|---|---|---|
| Procurement Analyst | Upload supplier files; compare quoted prices, delivery/warranty and missing terms; recommend under the declared price-first rubric with citations | Restricted parsers, fragment sanitization, untrusted evidence snapshots, outbound DLP, no unauthorized mock email |
| Web Research Agent | Retrieve explicit public HTTPS pages through a pinned-address reader; compare/summarize and cite released facts | DNS/private-host/redirect limits; all returned HTML/text inspected before context assembly |
| Developer Assistant | Review a fixed inert repository; identify quantity-validation bugs; propose a minimal patch and validation steps | README and other supplied repository material are untrusted; no shell, executed tests, privileged files or unrestricted network |

The core modules are `firewall.py`, `api.py`, `inspection.py`, `extractors.py`, `parsing.py`, `parser_worker.py`, `linux_guard.py`, `gate1.py`, `network.py`, `groq_ai.py`, `semantic.py`, `agents.py`, `evaluation.py` and bounded `storage.py`; `frontend/src` provides the real React/TypeScript console.

Tier 1/Tier 2 declared profiles cover UTF-8 text, static HTML, PDF text/metadata/annotations, DOCX XML/comments, XLSX cells/hidden sheets/comments, bounded recursive ZIP and partial English image OCR/metadata. Filenames and internal provenance are inspected. Known signature conflicts, malformed files and processing-limit failures are rejected. Original whole files are never certified SAFE.

Seven engineering attack categories are instruction override, role change, secret extraction, tool abuse, credential theft, encoded instruction and indirect injection. This is authored working coverage, not an official F3 award or proof against every variant.

## AI justification

Generation uses Groq `openai/gpt-oss-20b`; semantic inspection uses `meta-llama/llama-prompt-guard-2-86m`. Deterministic rules, decoders, parsers, disclosure restrictions and authorization handle enforceable decisions. Prompt Guard runs only for bounded ambiguous instruction cues and never grants tool authority.

Actual calibration recovered two rule-missed attacks out of eight authored attacks, with no added alerts on eight benign inputs. Reserved authored variants recovered three of four rule-missed attacks, with no added alerts on four benign inputs. Those small samples are not general accuracy claims. A hosted semantic-only comparison showed B did not detect a paraphrase while C did; both completed the task, so that observation demonstrates incremental detection, not additional agent-level prevention. A retained evasion fixture was missed and caused unknown/refused outcomes.

Detector scores are raw uncalibrated signals. Actual generation/classifier calls, tokens and latency are exposed; currency cost is not invented. Contextual LLM escalation remains disabled.

Release decision: **READY WITH DISCLOSED LIMITATIONS**. All required A–G workflows have recorded hosted evidence. Seven main authored categories pass the protected comparisons; the broader nine-attack routed recall is 8/9, below the proposed 90% target. One provider-429 configuration and the semantic evasion remain in the published evidence.

## Evidence and release decision

Use [Release checklist](docs/RELEASE_CHECKLIST.md) for the final decision and A–G hosted evidence, [Evaluation](EVALUATION.md) for measured corpus/results/uncertainty, [Implementation audit](docs/IMPLEMENTATION_AUDIT.md) for resolved defects, and [Known limitations](docs/KNOWN_LIMITATIONS.md) for excluded capabilities. All metrics are measurements on their stated samples, not claims of universal protection.

[Architecture](ARCHITECTURE.md) contains the overall platform/inspection pipeline plus context assembly, action authorization, shared three-agent integration and Attack Lab diagrams. [API integration](docs/API_INTEGRATION.md), [Deployment](DEPLOYMENT.md), [Security](SECURITY.md), [Coverage](COVERAGE.md), [Agents](AGENTS.md) and [README](README.md) describe the implemented system.

## Reproducible five-minute walkthrough

Prepare the free Render service before presenting; open the console and authenticate. Use the public synthetic files in [demo-fixtures](docs/demo-fixtures). All side effects are mock operations. Pre-run longer comparisons if cold starts would disrupt the five-minute presentation; clearly show their original measurement timestamps.

| Time | Actual demonstration |
|---|---|
| 0:00–0:30 | Explain external evidence versus authority. Show the working console and server-enforced boundaries |
| 0:30–1:00 | Open Agents: Procurement, Research and Developer have different profiles/resources but one firewall |
| 1:00–2:15 | Procurement: clear default pasted evidence; attach `vendor-a.txt`, `vendor-b.docx`, `vendor-c.pdf` and `malicious-proposal.xlsx`. Request price/delivery/warranty comparison. Inspect the hidden-sheet attack, original inert text and quarantined replacement |
| 2:15–3:00 | Show the real Groq recommendation for Vendor B and preserved commercial terms. Run/inspect a contained Attack Lab test: B/C's labelled forced unauthorized email is denied by the real broker, with zero emails executed. Do not claim the model made that forced proposal |
| 3:00–3:45 | Research: compare Orion/Vega using `https://agent-trust-firewall.vercel.app/research-fixture.html`; show malicious metadata/hidden HTML quarantined and factual brief retained. Developer: show fixed repository review/patch and quarantined README instruction |
| 3:45–4:30 | Attack Lab `semantic`: compare A/B/C detection, task completion, tokens and decisions. C detects the known paraphrase that B misses. Show the retained `semantic_evasion` miss/unknowns as a limit |
| 4:30–5:00 | Show measured evaluations, six architecture views and release limitations. Explain that authorization is independent of detector or model success |

Screenshots and final executed scenario evidence are linked from the release checklist and `submission-readiness-report.json`. Recording is unavailable in the enabled browser tools; no recording or portal submission is falsely claimed.
