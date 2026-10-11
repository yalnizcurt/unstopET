# Agent Trust Firewall Python client

This dependency-free HTTPS client invokes the existing protected service. It never receives a Groq credential. Install from the repository with `pip install ./sdk/python`, or use `PYTHONPATH=sdk/python` for the examples. TLS verification is required; redirects and environment proxies are disabled. Calls and responses are bounded and failures carry safe error codes.

```python
import os
from agent_trust_firewall import ATFClient

client = ATFClient(
    base_url=os.environ['ATF_API_URL'],
    api_key=os.environ['ATF_ACCESS_TOKEN'],
)
artifact = client.inspect_file('proposal.xlsx', open('proposal.xlsx', 'rb').read())
run = client.run_protected_agent(
    agent_id='procurement',
    task='Compare supplier proposals, disclose missing terms and cite released evidence.',
    artifact_ids=[artifact['id']],
)
print(run['output'])
print(client.get_timeline(run['id']))
print(client.get_security_summary(run['id']))
```

Task intent and evidence use separate fields. Hosted execution uses server profiles, Linux isolation, context snapshots, the Groq gateway, tool authorization and DLP. Requests cannot supply grants, system messages, credentials or authoritative trust labels. `integration_id` is a server-validated registration reference, not permission.

`inspect_file` alone is **INSPECTION_ONLY**: the external application must honor fragment dispositions, release scope and coverage gaps. It does not enforce the external application's model/tools. Only `run_protected_agent` uses our mandatory hosted runtime. Proxy/MCP integration modes are unavailable.

Other methods: `get_artifact`, `get_coverage`, `get_integrations`, `get_verification`, `get_events`, `get_runs`, `get_run`, `get_timeline`, `get_security_summary`, `compare_attack`. Results are dictionaries matching the versioned server contract. `ATFError` exposes a safe `code` and optional HTTP `status`. A failed task response includes a persisted run in central history; it never becomes a hardcoded success.

Shared demo access codes are server secrets for approved synthetic/public examples. Set them in the client environment through your approved secret manager; never commit them. Anyone with the code can read temporary demo history. Files are limited to 1 MB; records expire in 24 hours or on restart. No universal protection or enterprise tenant identity is promised.
