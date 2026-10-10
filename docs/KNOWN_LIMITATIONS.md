# Known limitations

The supported hackathon workflow is synthetic/public input, one admitted mutating job, three fixed protected agent profiles and contained external effects. It does not promise universal prompt-injection immunity or enterprise production readiness.

| Limitation | Current behavior / consequence |
|---|---|
| Shared demo identity | All access-code holders see retained demo records. No multi-user tenant authentication; use public/synthetic data only |
| Temporary live storage | SQLite records disappear on Render restart/redeploy and expire after 24 hours; reads prune expired rows. No durable user audit database was provisioned. Public versioned evaluation archives are labelled original measurements |
| Model persuasion / semantic misses | Rules and Prompt Guard miss some indirect and multilingual cases. The retained context-laundering test causes refusals and unknown attacker outcomes; it is not counted as prevention or task success |
| Generated analysis and citations | Groq output can contain inaccurate reasoning, suggested code or exact citation offsets. Source IDs, released evidence and actual broker records are available for review; business assertions and inert patches are not automatically certified or executed |
| Small authored evaluation | Repeated phrases across formats and few benign/held-out cases do not establish general recall, ≤5% false positives, ≥95% prevention or official D2 reliability. No independent security certification or official F3/D2 score |
| Limited DLP | Configured plain and bounded single-layer Base64 markers plus confidential lineage; no universal PII classification, arbitrary encoding deobfuscation or automatic business-document confidentiality inference |
| Declared-channel file support | PDF raster/complex objects, Office embedded binary objects and rendered layouts are withheld. HTML external/dynamic/media/style channels are reported as gaps. Exact document visual rendering is not performed |
| Imperfect image OCR | English pixel text and metadata only; always partial. QR decoding, recognition guarantees and multimodal image understanding are absent |
| Unsupported Tier 3 | PPTX, audio/video, legacy/binary formats and generic email-container adapters remain unsupported |
| Disabled advanced defenses | Persistent memory, cross-source correlation, contextual LLM escalation and autonomous red-team generation are not implemented or advertised as active |
| Restricted developer capability | Fixed synthetic repository and inert patch proposals; no shell, executed tests, arbitrary repository access or filesystem writes |
| Restricted research capability | Up to two explicit public HTTPS sources; no autonomous search, private hosts, redirects, arbitrary API/MCP adapters or active-page browser execution |
| Mock side effects | No live email, purchasing or repository mutation. Actual authorization/envelope/dispatch behavior is tested against contained mock sinks. Forced containment proposals are distinct from model-generated proposals |
| Demo availability / load | Free Render can sleep, cold-start or restart. Only one mutating job is admitted and 15/minute; no distributed queue or high-concurrency load qualification |
| Native Mac runtime | Disabled after earlier containment failure; all enabled protected execution requires the verified Linux boundary |
| Submission portal / recording | Portal fields and submission have not been verified or sent. Enabled browser tools support screenshots, not recording; the package supplies a timed walkthrough and screenshots |

These limits do not enable an alternative execution path. Unsupported capabilities stay disabled, incomplete regions remain withheld, and model/provider failures remain explicit. A future enterprise release needs independent evaluation, tenant identity, authorized durable storage, operational monitoring and capability-specific containment tests before enablement.
