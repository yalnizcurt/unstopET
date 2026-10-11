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
            Public demo configuration. Provider secrets stay on the server; this page is read-only.
          </p>
        </div>
      </div>
      <div className="notice subtle-notice">
        No login required. The server creates an isolated temporary browser workspace using an HttpOnly cookie. Use synthetic or public data only. Shared request and AI-operation limits apply; existing records remain readable when new AI work is disabled.
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
        {Object.entries(settings).filter(([key]) => key !== "demo_limits").map(([k, v]) => (
          <div className="boundary-row" key={k}>
            <span>{k.replaceAll("_", " ")}</span>
            <span className="subtle">{String(v)}</span>
          </div>
        ))}
      </section>
      {settings.demo_limits && (
        <section className="panel">
          <h3>Server-enforced demo limits</h3>
          {Object.entries(settings.demo_limits).map(([key, value]) => (
            <div className="boundary-row" key={key}>
              <span>{key.replaceAll("_", " ")}</span>
              <span className="subtle">{value !== null && typeof value === "object" ? JSON.stringify(value) : String(value)}</span>
            </div>
          ))}
          <p className="subtle">Limits apply to this session and shared service capacity. Reaching the processing cap stops new operations; existing records remain available until they expire.</p>
        </section>
      )}
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
