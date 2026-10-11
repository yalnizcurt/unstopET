# Agent Trust Firewall Python client

This dependency-free HTTPS client invokes the public demonstration service. No login, demo code or Groq credential is required. Install with `pip install ./sdk/python`, or use `PYTHONPATH=sdk/python` for the examples. TLS verification is required; redirects and environment proxies are disabled. Calls and responses remain bounded, and failures carry safe error codes.

```python
from pathlib import Path
from agent_trust_firewall import ATFClient

client = ATFClient('https://agent-trust-firewall-api.onrender.com')
artifact = client.inspect_file('proposal.xlsx', Path('proposal.xlsx').read_bytes())
run = client.run_protected_agent(
    agent_id='procurement',
    task='Compare supplier proposals, disclose missing terms and cite released evidence.',
    artifact_ids=[artifact['id']],
)
print(run['output'])
print(client.get_timeline(run['id']))
print(client.get_security_summary(run['id']))
```

## Anonymous sessions and migration

The first request lazily calls `POST /api/v1/demo/session` with JSON `{}` and `X-ATF-Demo: 1`. The server returns a host-only `__Host-atf-demo` cookie with `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/` and a 24-hour lifetime. A per-client `CookieJar` retains it; subsequent requests send the cookie to the configured HTTPS service. Mutations also send `X-ATF-Demo: 1`. The header is a CSRF guard, not identity or permission. Session identity is server-issued and never supplied in JSON.

Keep using the same `ATFClient` instance to inspect its artifacts and runs. A new instance establishes a separate visitor session; another SDK client or browser cannot read this client's records. There is no cookie export/import or browser-session adoption feature. Cookies are not written to disk or printed. Records and anonymous sessions expire after 24 hours and can disappear on a free Render restart/redeploy. The global 300-record cap can evict history sooner; record lists return at most 100 items. An expired-session response is explicit; create a new client and upload the synthetic inputs again. The SDK does not silently restart a failed task in a new session.

For source compatibility, `ATFClient(base_url, api_key=None)` still accepts an old second argument. It is ignored, not retained, and never sent as a bearer token. Remove `ATF_ACCESS_TOKEN` from examples and use `ATFClient(base_url)`; do not retrieve a code from Render. Earlier token-based evaluation/video reports retain their historical source and access behavior.

## Security scope

Task intent and evidence use separate fields. Hosted execution uses server profiles, Linux isolation, context snapshots, the Groq gateway, tool authorization and DLP. Requests cannot supply grants, system messages, credentials or authoritative trust labels. `integration_id` is a server-validated registration reference, not permission. Anonymous access does not enable unrestricted tools or live side effects.

`inspect_file` alone is **INSPECTION_ONLY**: the external application must honor fragment dispositions, release scope and coverage gaps. It does not enforce the external application's model/tools. Only `run_protected_agent` uses our mandatory hosted runtime. Proxy/MCP integration modes are unavailable.

Other methods: `get_artifact`, `get_coverage`, `get_integrations`, `get_verification`, `get_events`, `get_runs`, `get_run`, `get_timeline`, `get_security_summary`, `compare_attack`. Results match the versioned server contract. `ATFError` exposes a safe `code`, optional HTTP `status`, and a validated `run_id` for a retained failed task. It never echoes raw provider diagnostics.

| Error | Response and recovery |
|---|---|
| `DEMO_SESSION_REQUIRED` | HTTP 401; expired, missing or unknown server session. Start a new client; prior records are not transferred. |
| `DEMO_RATE_LIMITED` | HTTP 429; session/IP/global request cap reached. Wait before making another request. |
| `DEMO_DAILY_BUDGET_EXHAUSTED` | HTTP 429; application daily operation cap reached. Non-inference exploration remains available. |
| `DEMO_INFERENCE_DISABLED` | HTTP 429; new inference is disabled server-side. Explore the available read-only information. |

The SDK does not automatically retry these responses. Server limits bound requests, uploads and admitted inspection/task/evaluation jobs; the application operation cap is not a measured monetary or token budget. Free redeploys reset its temporary counters; provider-account limits remain authoritative. IP caps use the observed connection peer, so shared proxies can aggregate visitors. Uploads are limited to 1 MB each, existing file-count/model-turn/time budgets apply, and raw binaries are discarded after inspection. Use synthetic/public data only. No universal protection, durable audit storage or enterprise tenant identity is promised.
