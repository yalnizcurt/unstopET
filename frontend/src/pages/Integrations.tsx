import { useState } from "react";
import { Badge, type Row } from "../components/Common";
import { API } from "../app/api";
const snippet = `import os\nfrom pathlib import Path\nfrom agent_trust_firewall import ATFClient\n\nclient = ATFClient(\n    base_url=os.environ['ATF_API_URL'],\n    api_key=os.environ['ATF_ACCESS_TOKEN'],\n)\nartifact = client.inspect_file('proposal.xlsx', Path('proposal.xlsx').read_bytes())\nrun = client.run_protected_agent(\n    agent_id='procurement',\n    task='Compare supplier proposals and cite evidence.',\n    artifact_ids=[artifact['id']],\n)\nprint(run['output'])\nprint(client.get_timeline(run['id']))`;
export function Integrations({
  integrations,
  go,
  details,
}: {
  integrations: Row[];
  go: (p: string) => void;
  details: (id: string) => void;
}) {
  const [copyStatus, setCopyStatus] = useState("");
  async function copyExample() {
    try {
      await navigator.clipboard.writeText(snippet);
      setCopyStatus("Copied");
    } catch {
      setCopyStatus("Select and copy the example below.");
    }
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">CONNECT → PROTECT → EXECUTE</span>
          <h1>Integrations</h1>
          <p className="subtle">
            Use a registered hosted runtime or call inspection from your own
            application.
          </p>
        </div>
        <a
          className="primary"
          href={API + "/api/docs"}
          target="_blank"
          rel="noreferrer"
        >
          API documentation
        </a>
      </div>
      <section className="panel">
        <h3>Protect an agent</h3>
        <ol className="onboarding">
          <li>Choose hosted execution for mandatory server-side boundaries.</li>
          <li>
            Configure the approved demo access code in your client environment.
          </li>
          <li>
            Submit task intent separately from evidence using the Python SDK.
          </li>
          <li>
            Check version-matching verification and inspect the actual run.
          </li>
        </ol>
        <p className="subtle">
          Registration is server-owned. Clicking a button never creates
          privileges or a verified connection.
        </p>
      </section>
      <div className="agent-grid">
        {integrations.map((i) => (
          <section className="panel" key={i.id}>
            <Badge value={i.lifecycle_status} />
            <h3>{i.name}</h3>
            <p className="subtle">{i.description}</p>
            <Badge value={i.integration_type} />
            <p className="subtle">{i.deployment_mode}</p>
            <button className="secondary" onClick={() => details(i.id)}>
              Capabilities and verification
            </button>
          </section>
        ))}
      </div>
      <section className="panel">
        <div className="panel-title">
          <h3>Python SDK · hosted protected execution</h3>
          <button
            className="secondary"
            onClick={copyExample}
          >
            Copy example
          </button>
        </div>
        <p className="subtle" role="status">{copyStatus}</p>
        <pre>{snippet}</pre>
        <p className="subtle">
          Install from this repository: <code>pip install ./sdk/python</code>.
          No Groq key belongs in the client.
        </p>
        <a
          className="text-button"
          href="https://github.com/yalnizcurt/unstopET/tree/main/examples/external_procurement_client"
          target="_blank"
          rel="noreferrer"
        >
          Independent reference application
        </a>{" "}
        ·{" "}
        <button className="text-button" onClick={() => go("Runtime Activity")}>
          View incoming executions
        </button>
      </section>
      <div className="notice">
        Inspection-only mode provides signals and released-fragment guidance; it
        does not enforce your external model or tools. Inference proxy and MCP
        gateway are unavailable. Shared demo authentication is not enterprise
        tenant identity.
      </div>
    </>
  );
}
export function AgentDetails({
  integration,
  go,
}: {
  integration: Row | null;
  go: (p: string) => void;
}) {
  if (!integration)
    return (
      <section className="panel">
        <h1>Select a registered integration</h1>
        <button className="secondary" onClick={() => go("Integrations")}>
          Integrations
        </button>
      </section>
    );
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">SERVER-OWNED INTEGRATION</span>
          <h1>{integration.name}</h1>
          <p className="subtle">{integration.description}</p>
        </div>
        <Badge value={integration.lifecycle_status} />
      </div>
      <section className="panel">
        <h3>Security boundaries</h3>
        <div className="boundary-flow">
          {integration.required_security_boundaries.map((b: string) => (
            <div key={b}>
              <strong>{b.replaceAll("_", " ")}</strong>
              <Badge
                value={
                  integration.verified_security_boundaries.includes(b)
                    ? "VERIFIED_DECLARED_SCOPE"
                    : "UNVERIFIED"
                }
              />
            </div>
          ))}
        </div>
        <details>
          <summary>Verification evidence</summary>
          <pre>{JSON.stringify(integration.verification, null, 2)}</pre>
        </details>
        <p className="subtle">
          Version-matching Linux tests plus startup containment verify the
          declared hosted boundary. Health alone does not establish protection.
          No universal prompt-injection immunity is claimed.
        </p>
        <p className="subtle">
          Last verified:{" "}
          {integration.last_verified_at || "No version-matching evidence"} ·
          Last execution:{" "}
          {integration.last_execution_at || "No retained execution"}
        </p>
      </section>
      <section className="panel">
        <h3>Capabilities and limits</h3>
        <div className="chips">
          {integration.available_tools.map((t: string) => (
            <Badge key={t} value={t} />
          ))}
        </div>
        <p className="subtle">
          Inputs: {integration.supported_inputs.join(", ")} ·{" "}
          {integration.policy_profile} · {integration.deployment_mode}
        </p>
        <ul>
          {integration.limitations.map((l: string) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
        <div className="pillrow">
          <a
            className="secondary"
            href={API + "/api/docs"}
            target="_blank"
            rel="noreferrer"
          >
            Verification API
          </a>
          <button className="secondary" onClick={() => go("Runtime Activity")}>
            Runtime activity
          </button>
          <button className="secondary" onClick={() => go("Security Policies")}>
            Policy
          </button>
        </div>
      </section>
    </>
  );
}
