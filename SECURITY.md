# Security boundaries and limitations

## Enforced boundaries

- Authentication precedes privileged API work; one shared demo principal is bound server-side. Browser roles, trust labels, tenant flags and snapshot identifiers cannot establish authority. Strict versioned request schemas reject unknown fields.
- System policy and agent instructions are assembled on the server. Quoted/pasted/attached content remains untrusted. Mixed quoted instructions are demoted conservatively.
- The child agent has an empty credential environment, no permitted general network syscalls, no shell/exec/fork and no protected-file access. Startup runs actual positive-control containment probes before listening or using credentials. Missing Linux isolation fails closed.
- Parsers import trusted libraries before receiving upload bytes, then enter the same irreversible Linux restrictions. English OCR uses a preloaded native Tesseract library and read-only language data; it adds no shell, exec, fork or network syscall permission. Parent/worker protocols have size/time limits. Macros, scripts, formulas and embedded objects are never executed.
- All registered tools go through the broker. Research uses only explicit user-selected HTTPS URLs, resolves and rejects non-global addresses, pins the chosen address for verified TLS, disables redirects/proxies and bounds media and bytes. Synthetic repository reads cannot escape the fixed registry.
- Tool responses are parsed and inspected before import into a new server snapshot. They cannot overwrite system instructions or grant permissions.
- Mock email preparation checks server destination authority separately from DLP. Dispatch rechecks current permissions, snapshot, policy, destination and immutable payload; single-use permits prevent replay. The demo never sends live email.
- Plain and bounded single-layer Base64 encoded secret markers/provider-key patterns and confidential lineage are blocked at model egress and output/action release. Provider errors are returned as bounded codes; raw exception bodies, requests and credentials are not logged.
- Standalone and internal filenames are inspected; quarantined names are not reintroduced through model source labels. Known signature/extension conflicts are rejected. Files with unsupported regions are partial or unsupported. Release is limited to inspected fragments. No original whole-file SAFE claim is emitted. Semantic errors withhold affected fragments.

## Limits

This is a defense-in-depth prototype. Signature rules and Prompt Guard miss attacks, including indirect intent manipulation. Structural evidence wrappers do not guarantee model obedience. DLP is limited to configured patterns and sensitivity labels, not universal personal-data detection.

Shared demo authentication is not multi-tenant identity. Anyone with the demo access code can access retained demo records. Use synthetic/public inputs only. Raw upload bytes are discarded; inspected redacted fragments, task intent/output, events and evaluations can remain for 24 hours (maximum 300 records total, 100 per list). Free Render storage resets on redeploy; it is not a durable production audit store.

QR decoding, imperfect English pixel OCR, PDF raster/complex-object content, Office embedded objects and dynamic HTML are not comprehensively inspected. Unsupported portions are withheld. Memory and unrestricted connectors remain disabled. No production live email, shell or repository modification capability exists.

The gateway retries HTTP 429/503 once with bounded 250ms backoff. Other outages fail explicitly; no side-effect dispatch is automatically retried. Model requests and classifier calls have fixed budgets. No cost amount is invented; Groq billing remains authoritative.

## Evidence

`platform-linux-acceptance-report.json` records actual Linux checks and source hashes. `semantic-evaluation-report.json` and `semantic-heldout-report.json` record real Groq classifier measurements. These small authored sets do not establish general reliability or official hackathon F3/D2 achievement. The retained earlier Mac failure report documents why the native Mac agent runtime remains disabled.

Labelled forced-compromise tests call the real broker even when the model resists injection. Their denials are not model behavior or attacker-success measurements. Read-only access prunes expired records; public archived measurements retain original timestamps.

## Bounded runtime amendment

A server-owned tool registry permits only exact schemas and profile-approved released artifacts, fixed repository paths or previously approved page IDs. Supplier scoring uses released facts, not model-submitted numbers. Tool receipts are independently inspected and imported before a new snapshot. Reads cannot broaden grants; collection is single-use. Model/child proposals cannot mutate roles, policies, registry, evidence hashes or destination rules. The existing mandatory broker owns every operation.

The multi-step launcher is bounded by the existing 60-second task deadline, maximum three model turns and two tool requests. Legacy contained evaluation fixtures retain their one-response path. Review/invalid structured outputs and provider outages remain explicit failures with persisted trace. A fixed independent containment probe is labelled separately from model proposals. SDK redirects/proxies are disabled and its client errors do not echo raw service/provider bodies.

The console exposes decisions and references, not model chain-of-thought. Integration protection verification requires matching deployed module hashes in Linux acceptance evidence and startup isolation. External inspection-only clients are responsible for obeying verdicts and cannot claim mandatory hosted context/tool control.

The Groq gateway declares only server-selected local function schemas for the registered runtime. Provider function calls are inert proposals, revalidated by the existing mandatory broker; they do not execute on Groq. Built-in browser/code tools and remote MCP are absent. A server-controlled finishing choice after procurement scoring, a research read or at the third turn constrains completion and cannot grant privileges. Its output must be nonempty and passes release DLP. Provider reasoning fields are ignored. Legacy/A/B/C calls use the original text-only adapter and reject native tool calls.
