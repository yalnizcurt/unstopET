import { Badge, Empty, type Row } from "./Common";
export function ActivityTimeline({ events }: { events: Row[] }) {
  if (!events.length)
    return (
      <Empty text="No detailed runtime trace was recorded for this legacy or expired execution." />
    );
  return (
    <div className="activity-timeline">
      {events.map((e) => (
        <details className="fragment" key={e.event_id}>
          <summary>
            <span>
              <strong>
                {e.sequence}. {e.stage.replaceAll("_", " ")}
              </strong>
              <small>
                {e.operation} · {new Date(e.created_at).toLocaleTimeString()}
              </small>
              {e.origin === "FORCED_COMPROMISE_PROBE_NOT_MODEL_OUTPUT" && (
                <small className="probe-label">Forced containment test · not a model proposal</small>
              )}
              {e.stage === "TOOL_REQUEST" && (
                <small>{e.origin === "AUTHENTICATED_SOURCE_PLAN"
                  ? "User-selected source plan · brokered retrieval"
                  : "Agent proposal · execution requires broker authorization"}</small>
              )}
            </span>
            <Badge value={e.decision} />
          </summary>
          <p className="subtle">
            {e.reason_code || e.reason || "Recorded by the trusted server"}
          </p>
          {e.origin && <Badge value={e.origin} />}
          <pre>
            {JSON.stringify(
              Object.fromEntries(
                Object.entries(e).filter(
                  ([key]) =>
                    ![
                      "sequence",
                      "stage",
                      "operation",
                      "decision",
                      "result",
                      "created_at",
                    ].includes(key),
                ),
              ),
              null,
              2,
            )}
          </pre>
        </details>
      ))}
    </div>
  );
}
