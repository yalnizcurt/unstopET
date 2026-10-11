import React from "react";
import { FlaskConical, ChevronRight, AlertTriangle } from "lucide-react";
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
export function Evaluations(props: ViewProps) {
  const {
    page,
    go,
    setResult,
    scenario,
    surface,
    setComparison,
    setAgent,
    setScenario,
    setSurface,
    evaluations,
  } = props;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">MEASURED EVIDENCE</span>
          <h1>Evaluations</h1>
          <p className="subtle">
            Stored attack comparisons. Unknowns and failures remain visible.
          </p>
        </div>
        <button className="primary" onClick={() => go("Attack Lab")}>
          Run evaluation
          <FlaskConical size={16} />
        </button>
      </div>
      {evaluations.length ? (
        evaluations.map((e) => (
          <section className="panel" key={e.id}>
            <div className="panel-title">
              <div>
                <h3>
                  {e.category.replaceAll("_", " ")} · {e.surface}
                </h3>
                {e.origin && <Badge value={e.origin} />}
                <span className="subtle"> </span>
                <small>
                  {new Date(e.created_at).toLocaleString()} · {e.agent_id}
                </small>
              </div>
              <button
                className="text-button"
                onClick={() => {
                  setAgent(e.agent_id);
                  setScenario(e.scenario);
                  setSurface(e.surface);
                  setResult(null);
                  setComparison(e);
                  go("Attack Lab");
                }}
              >
                Inspect run
                <ChevronRight size={16} />
              </button>
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Configuration</th>
                    <th>Detected</th>
                    <th>Task success</th>
                    <th>Attack objective prevented</th>
                    <th>Simulated executions</th>
                    <th>Latency</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {e.results.map((r: Row) => (
                    <tr key={r.configuration}>
                      <td>{r.configuration}</td>
                      <td>{r.detection == null ? "—" : String(r.detection)}</td>
                      <td>
                        {r.task_success == null ? "—" : String(r.task_success)}
                      </td>
                      <td>
                        {r.attack_prevented == null
                          ? "Unknown"
                          : String(r.attack_prevented)}
                      </td>
                      <td>{r.unauthorized_simulated_tool_executions ?? "—"}</td>
                      <td>{r.seconds ?? "—"}s</td>
                      <td>
                        <Badge value={r.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="subtle">{e.scope}</p>
          </section>
        ))
      ) : (
        <section className="panel">
          <Empty text="No evaluation data. Run an actual contained test in Attack Lab." />
        </section>
      )}
      <div className="notice subtle-notice">
        <AlertTriangle size={16} /> These runs do not establish universal
        protection or certified F3/D2 reliability. Cost is not estimated; Groq
        billing is authoritative.
      </div>
    </>
  );
}
