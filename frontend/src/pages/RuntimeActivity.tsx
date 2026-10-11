import { Activity, ChevronRight, FileText } from "lucide-react";
import { Badge, Empty, Output, type Row } from "../components/Common";
import { ActivityTimeline } from "../components/ActivityTimeline";
export function RuntimeActivity({
  sessions,
  selected,
  setSelected,
  setInvestigate,
  go,
}: {
  sessions: Row[];
  selected: Row | null;
  setSelected: (r: Row) => void;
  setInvestigate: (r: Row) => void;
  go: (p: string) => void;
}) {
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">FROM AUTHORIZATION TO OUTPUT</span>
          <h1>Runtime activity</h1>
          <p className="subtle">
            Actual execution traces. Model reasoning stays private; decisions
            stay reviewable.
          </p>
        </div>
        <span className="subtle">{sessions.length} retained runs</span>
      </div>
      <div className="scan-grid">
        <section className="panel">
          <h3>Protected executions</h3>
          {sessions.length ? (
            sessions.map((s) => (
              <button
                className={
                  "artifact-row " + (selected?.id === s.id ? "selected" : "")
                }
                key={s.id}
                onClick={() => setSelected(s)}
              >
                <Activity size={18} />
                <span>
                  <strong>
                    {s.integration_id || s.agent_id}
                    {s.configuration ? " · Lab " + s.configuration : ""}
                  </strong>
                  <small>
                    {new Date(s.created_at).toLocaleString()} · {s.intent}
                  </small>
                </span>
                <Badge value={s.status} />
              </button>
            ))
          ) : (
            <Empty text="Run an agent or the external Python application to record activity." />
          )}
        </section>
        {selected ? (
          <section className="panel">
            <div className="panel-title">
              <h3>{selected.integration_id || selected.agent_id}</h3>
              <Badge value={selected.status} />
            </div>
            <p className="subtle mono hash">Run {selected.id}</p>
            {selected.origin && <Badge value={selected.origin} />}
            <p className="subtle">{selected.runtime}</p>
            <p className="subtle">
              Authorized task: {selected.authorized_intent || selected.intent}
            </p>
            <div className="mini-stats">
              <div>
                <strong>
                  {selected.timeline?.filter(
                    (e: Row) => e.stage === "MODEL_REQUEST",
                  ).length ?? "—"}
                </strong>
                <small>Recorded model requests</small>
              </div>
              <div>
                <strong>{selected.usage?.total_tokens ?? 0}</strong>
                <small>Generation tokens</small>
              </div>
              <div>
                <strong>{selected.emails_executed ?? 0}</strong>
                <small>Mock emails executed</small>
              </div>
            </div>
            {selected.error && (
              <div className="notice error">{selected.error}</div>
            )}
            <ActivityTimeline events={selected.timeline || []} />
            {selected.output && (
              <>
                <h3>Released output</h3>
                <Output value={selected.output} />
              </>
            )}
            <h4>Bound evidence</h4>
            {selected.artifacts?.map((a: Row) => (
              <button
                className="source-button"
                key={a.id}
                onClick={() => {
                  setInvestigate(a);
                  go("Threat Intelligence");
                }}
              >
                <FileText size={16} />
                <span>
                  {a.filename}
                  <small>
                    {a.inspection_status} · {a.release_scope}
                  </small>
                </span>
                <ChevronRight size={14} />
              </button>
            ))}
            <p className="subtle">
              A completed run means output was released. Legitimate-task
              correctness is scored separately in Security Lab.
            </p>
          </section>
        ) : (
          <section className="panel">
            <Empty text="Select a run to inspect its chronological security trace." />
          </section>
        )}
      </div>
    </>
  );
}
