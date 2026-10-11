import React from "react";
import { ArrowUpRight } from "lucide-react";
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
export function Settings(props: ViewProps) {
  const { page, health, settings, api, coverage } = props;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">DEPLOYMENT & CAPABILITIES</span>
          <h1>Workspace settings</h1>
          <p className="subtle">
            Actual server configuration. Secrets are never sent to this console.
          </p>
        </div>
      </div>
      <section className="panel">
        <h3>Connected service</h3>
        <div className="boundary-row">
          <span>API endpoint</span>
          <a href={API + "/api/v1/health"} target="_blank" rel="noreferrer">
            {API}
            <ArrowUpRight size={14} />
          </a>
        </div>
        {Object.entries(settings).map(([k, v]) => (
          <div className="boundary-row" key={k}>
            <span>{k.replaceAll("_", " ")}</span>
            <span className="subtle">{String(v)}</span>
          </div>
        ))}
      </section>
      <section className="panel">
        <h3>Supported format coverage</h3>
        <div className="coverage-list">
          {coverage.formats?.map((f: Row) => (
            <div key={f.format}>
              <strong>{f.format}</strong>
              <Badge value={f.status} />
              <small>
                Inspected: {f.channels.join(", ") || "None"}
                <br />
                Limitations: {f.gaps.join(", ")}
              </small>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
