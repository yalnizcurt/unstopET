# Supported agents and engineering constraints

All agents use `Firewall`, server-issued context snapshots, the same shared inspection pipeline, the isolated Linux runtime and the Groq gateway. Do not add direct model, network, filesystem, shell, credential or MCP access to the child runtime. New capabilities require containment and authorization tests before enablement. Keep policy/coverage truthful and never log credentials or raw provider errors.

| Agent | Working capability | Limits |
|---|---|---|
| Procurement Analyst | Extracts supplied supplier facts, compares price then available delivery/warranty, cites evidence and recommends | No live purchasing/email; missing terms must remain missing |
| Web Research Agent | Reads up to two user-selected public HTTPS pages through the pinned-address broker; inspects returned static HTML/text; creates a cited brief | No autonomous search engine; no scripts, private hosts, redirects or arbitrary network tools |
| Developer Assistant | Reads a fixed synthetic repository through the broker; explains code/bugs and proposes inert patch text | No shell, test execution, live repo writes or unrestricted filesystem |

Profiles are defined server-side in `agents.py`. Agents cannot edit profiles, grants, destination allowlists, policy or persistent memory. Memory is disabled and rejects writes.

Attack Lab can apply a common synthetic procurement outcome task to any registered profile; this is a matched security fixture, not proof that each profile completed its distinctive business workflow. Hosted smoke tests must demonstrate those separate workflows.

Tests: Linux Docker acceptance plus versioned API/parser tests; frontend `npm run build`. The native Mac agent path remains unavailable; use the verified Linux runtime for actual execution.
