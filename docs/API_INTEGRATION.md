# API integration

- Production API: https://agent-trust-firewall-api.onrender.com
- Interactive reference: https://agent-trust-firewall-api.onrender.com/api/docs
- OpenAPI schema: https://agent-trust-firewall-api.onrender.com/api/openapi.json
- Console: https://agent-trust-firewall.vercel.app

Health and API documentation are public and contain no credentials or retained user records. Every privileged route requires `Authorization: Bearer <APP_ACCESS_TOKEN>`. This is the shared demo access code configured in Render; never use the Groq credential in a browser or client integration. Swagger's Authorize control accepts the demo code. Browser origins must match the server's explicit allowlist.

## Task flow

1. Inspect a file with `POST /api/v1/artifacts`, JSON `{ "filename": "supplier.txt", "data": "<base64 file bytes>" }`. The 1 MB file cap, strict magic/extension checks, parsing limits and isolated worker apply.
2. Inspect the returned `inspection_status`, `release_scope`, `uninspected_channels`, `fragments`, `routing` and `safe_claim`. `COMPLETE` describes declared channels; it never certifies universal safety. `UNSUPPORTED` cannot be imported into context.
3. Send `POST /api/v1/tasks` with structured authenticated intent and separate evidence:

```json
{
  "agent_id": "procurement",
  "intent": "Compare quoted prices, delivery and warranty. Recommend using the declared rubric and cite evidence.",
  "artifact_ids": ["<server-returned artifact ID>"],
  "evidence": []
}
```

For Research use `agent_id: "research"` and up to two explicit public HTTPS `urls`. The controlled reader rejects private addresses, redirects, unsupported media and oversized responses. For Developer use `agent_id: "developer"` with `use_demo_repository: true`. Repository contents are fixed inert server fixtures; no path, shell command or arbitrary repository selection is accepted.

The task response includes actual Groq output, usage, provider retry metrics, tool reads, released artifact provenance, broker decisions, runtime status and mock email execution count. `COMPLETED` means the response was released successfully; arbitrary business-task correctness is not automatically inferred. Evaluation's task-success metric uses an explicit synthetic outcome check.

## Investigation and evaluation

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/agents` | Server profiles, supported tools and policy version |
| `GET /api/v1/coverage` | Versioned format manifest and disabled capabilities |
| `GET /api/v1/artifacts/{id}` | Authorized inert fragment investigation |
| `GET /api/v1/artifacts/{id}/coverage` | Completeness and release scope |
| `GET /api/v1/sessions`, `/sessions/{id}` | Retained task history |
| `GET /api/v1/events` | Actual inspection, broker and contained evaluation events |
| `GET /api/v1/attacks` | Registered synthetic scenarios and surfaces |
| `POST /api/v1/attacks/run` | Matched A/B/C comparison: agent ID, scenario ID, surface |
| `GET /api/v1/evaluations` | Actual fresh or explicitly archived measurements |
| `GET /api/v1/policies`, `/settings`, `/overview` | Read-only policy, deployment state and observed counts |

A lab request example is `{ "agent_id": "procurement", "scenario": "semantic", "surface": "text" }`. Protected configurations include a forced unauthorized-action probe labelled `FORCED_COMPROMISE_PROBE_NOT_MODEL_OUTPUT`. Its broker decision is independent of whether the model follows the attack and does not alter the model-persuasion score.

## Errors and authority

401 means no valid demo code; 403 means forbidden browser origin; 413 means body limits/content type; 422 supplies a bounded validation/security/budget code; 503 means unavailable processing or failed isolation. Mutating work is limited to one job and 15 admitted jobs/minute. Groq 429/503 is retried once with bounded backoff; there is no uncontrolled retry or queued side effect.

Do not supply roles, system prompts, trust labels, tenant IDs, authorization flags, model credentials or context snapshots. These cannot establish authority and strict request schemas reject extra fields. Tool execution approval is not exposed to the agent or public API. DLP can deny an otherwise permitted disclosure.

All code holders share one synthetic demo principal. This is not a multi-tenant production API. Temporary live records expire after 24 hours and can disappear on Render restart/redeploy; public evaluation archives retain their original measurement time and scope. Use only public/synthetic inputs.

## Registered integrations and multi-step runs

The dependency-free Python SDK is in `sdk/python`; the separate executable client is `examples/external_procurement_client/app.py`. It uploads the public fixtures over HTTPS and calls the hosted protected runtime. No model credential or local inference is involved. See [SDK instructions](../sdk/python/README.md) and [platform demo](PLATFORM_DEMO.md).

| Endpoint | Contract |
|---|---|
| `GET /api/v1/integrations` | Server-owned registrations; lifecycle, profiles, boundaries and limits |
| `GET /api/v1/integrations/{id}` | Integration details; clients cannot edit grants or register arbitrary tools |
| `GET /api/v1/integrations/{id}/capabilities` | Declared inputs and narrow tools |
| `GET /api/v1/integrations/{id}/verification` | Exact-source Linux acceptance and actual startup containment; connectivity alone is insufficient |
| `GET /api/v1/integrations/{id}/runs` | Retained execution history for that registration |
| `GET /api/v1/runs`, `/runs/{id}` | Actual business runs and separately labelled A/B/C fixtures |
| `GET /api/v1/runs/{id}/timeline` | Correlated chronological decisions without private model reasoning |
| `GET /api/v1/runs/{id}/security-summary` | Actual releases, tool requests, denials, coverage and unknown utility |
| `GET /api/v1/incidents`, `/incidents/{id}` | Actual threat/denial evidence tied to source and run |

A task can specify a registered `integration_id`; it does not grant authority. The Python procurement client selects `python-sdk-procurement`. An inspection-only registration cannot invoke a protected profile. Profiles and allowlists stay server-owned.

The child is bounded to three model turns and two model-selected tool requests. Local Groq function declarations produce proposals only; `Firewall.handle` independently validates current snapshots, profile arguments, released resources and DLP. Groq browsing, remote MCP and code-execution tools are never declared. The finishing function returns public response data, never an executable action. Default/legacy provider calls continue rejecting native tool proposals.

Tool receipts traverse the shared parser/inspection/release path before the next server-issued snapshot. Failed tasks retain a run ID and timeline; a 422 with `run_id` can be investigated through the run endpoints. `containment_probe: true` requests one fixed synthetic unauthorized-email denial, labelled independently from model output; it never authorizes sending an email. Memory and all live side effects remain disabled.
