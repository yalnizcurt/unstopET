import React from "react";
import { LockKeyhole } from "lucide-react";
import {
  Badge,
  Empty,
  Output,
  type Row,
  type ViewProps,
} from "../components/Common";
import { EventTable } from "../components/EventTable";
import { ArtifactInspector } from "../components/ArtifactInspector";
import { API } from "../app/api";
export function Policies(props: ViewProps) {
  const { page, overview, settings, agents, evidence, policies } = props;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">SERVER-MANAGED AUTHORITY</span>
          <h1>Security policies</h1>
          <p className="subtle">
            Versioned, enforced settings. Models and browser requests cannot
            modify them.
          </p>
        </div>
        <Badge value={"VERSION " + policies.version} />
      </div>
      <div className="overview-grid">
        <section className="panel">
          <h3>Instruction authority</h3>
          <div className="authority">
            {policies.authority?.map((a: string, i: number) => (
              <div key={a}>
                <span>{i + 1}</span>
                <strong>{a.replaceAll("_", " ")}</strong>
                <small>
                  {i === 2
                    ? "Facts only; cannot authorize effects"
                    : "Server-authenticated channel"}
                </small>
              </div>
            ))}
          </div>
          <div className="notice">
            <LockKeyhole size={16} /> External evidence never grants
            permissions.
          </div>
        </section>
        <section className="panel">
          <h3>Execution and disclosure</h3>
          {[
            ["Email", policies.external_email],
            ["Memory", policies.memory],
            ["Unknown content", policies.unsupported],
            ["Incomplete scans", policies.partial_release],
          ].map(([key, value]) => (
            <div className="boundary-row" key={key}>
              <span>{key}</span>
              <span className="subtle mono">{value}</span>
            </div>
          ))}
        </section>
        <section className="panel">
          <h3>Inspection budgets</h3>
          {Object.entries(policies.budgets || {}).map(([key, value]: any) => (
            <div className="boundary-row" key={key}>
              <span>{key.replaceAll("_", " ")}</span>
              <strong>{value.toLocaleString()}</strong>
            </div>
          ))}
        </section>
        <section className="panel">
          <h3>Policy dispositions</h3>
          <div className="chips">
            {policies.disposition?.map((d: string) => (
              <Badge key={d} value={d} />
            ))}
          </div>
          <p className="subtle">
            Detection is evidence for policy. It does not grant tool authority
            or promise universal protection.
          </p>
        </section>
      </div>
      <section className="panel">
        <h3>Registered profile capabilities</h3>
        {agents.map((a) => (
          <div className="boundary-row" key={a.id}>
            <span>{a.name}</span>
            <span className="subtle">
              {a.tools.join(", ")}
              <br />
              {a.authorized_resources}
              <br />
              Explicit user-selected public HTTPS; no live email
              <br />
              Outbound policy: {a.outbound_policy}
            </span>
          </div>
        ))}
      </section>
    </>
  );
}
