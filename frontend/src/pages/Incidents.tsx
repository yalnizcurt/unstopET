import { Badge, Empty, type Row } from "../components/Common";
import { ArtifactInspector } from "../components/ArtifactInspector";
export function Incidents({
  incidents,
  selected,
  open,
  go,
  openRun,
}: {
  incidents: Row[];
  selected: Row | null;
  open: (id: string) => void;
  go: (p: string) => void;
  openRun: (r: Row) => void;
}) {
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">INVESTIGATE OBSERVED DECISIONS</span>
          <h1>Security incidents</h1>
          <p className="subtle">
            Detections, incomplete inspections and denials. A signal does not
            prove attacker success.
          </p>
        </div>
        <button className="secondary" onClick={() => go("Event Log")}>
          All security events
        </button>
      </div>
      <div className="scan-grid">
        <section className="panel">
          <h3>Recorded incidents</h3>
          {incidents.length ? (
            incidents.map((e) => (
              <button
                className="artifact-row"
                key={e.id || e.event_id}
                onClick={() => open(e.id || e.event_id)}
              >
                <span>
                  <strong>{e.operation}</strong>
                  <small>
                    {e.reason_code ||
                      e.reason ||
                      e.signals?.map((s: Row) => s.category).join(", ")}{" "}
                    · {new Date(e.created_at).toLocaleString()}
                  </small>
                </span>
                <Badge value={e.result} />
              </button>
            ))
          ) : (
            <Empty text="No detections or denied operations in retained live records." />
          )}
        </section>
        {selected ? (
          <div>
            <section className="panel">
              <div className="panel-title">
                <h3>{selected.event.operation}</h3>
                <Badge value={selected.event.result} />
              </div>
              <pre>{JSON.stringify(selected.event, null, 2)}</pre>
              <p className="subtle">{selected.outcome_note}</p>
              {selected.run && (
                <>
                  <p className="subtle">
                    Run {selected.run.id} · {selected.run.status}
                  </p>
                  <button
                    className="secondary"
                    onClick={() => openRun(selected.run)}
                  >
                    Inspect execution timeline
                  </button>
                </>
              )}
            </section>
            {selected.artifact && (
              <ArtifactInspector record={selected.artifact} />
            )}
          </div>
        ) : (
          <section className="panel">
            <Empty text="Select an incident to inspect the original inert evidence, release decision and linked execution." />
          </section>
        )}
      </div>
    </>
  );
}
