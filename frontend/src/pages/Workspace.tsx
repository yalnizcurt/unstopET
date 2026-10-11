import React from "react";
import {
  ShieldCheck,
  Activity,
  ChevronRight,
  LockKeyhole,
  Upload,
  Play,
  X,
  FileText,
} from "lucide-react";
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
export function Workspace(props: ViewProps) {
  const {
    page,
    go,
    health,
    agents,
    setIntent,
    setUrls,
    setRepo,
    setAttachments,
    setResult,
    active,
    agent,
    intent,
    evidence,
    urls,
    repo,
    attachments,
    result,
    action,
    api,
    busy,
    upload,
    refresh,
    setEvidence,
    artifacts,
    setInvestigate,
    filter,
    coverage,
  } = props;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">PROTECTED WORKSPACE</span>
          <h1>{active?.name}</h1>
          <p className="subtle">{active?.description}</p>
        </div>
        <button className="secondary" onClick={() => go("Agents")}>
          All agents
        </button>
      </div>
      <div className="workspace-grid">
        <div>
          <form
            className="panel task-form"
            onSubmit={(e) => {
              e.preventDefault();
              action(async () => {
                const r = await api("tasks", {
                  agent_id: agent,
                  intent,
                  evidence: evidence.trim() ? [evidence] : [],
                  artifact_ids: attachments,
                  urls:
                    agent === "research"
                      ? urls
                          .split("\n")
                          .map((x) => x.trim())
                          .filter(Boolean)
                      : [],
                  use_demo_repository: agent === "developer" && repo,
                  containment_probe: agent === "procurement",
                });
                setResult(r);
                await refresh();
              });
            }}
          >
            <div className="panel-title">
              <h3>Authorized task</h3>
              <LockKeyhole size={16} />
            </div>
            <label>
              Your instruction
              <textarea
                value={intent}
                onChange={(e) => setIntent(e.target.value)}
                required
                rows={3}
              />
            </label>
            {agent === "research" && (
              <label>
                Permitted public HTTPS sources (up to two)
                <textarea
                  rows={2}
                  value={urls}
                  onChange={(e) => setUrls(e.target.value)}
                />
              </label>
            )}
            {agent === "developer" && (
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={repo}
                  onChange={(e) => setRepo(e.target.checked)}
                />{" "}
                Include the synthetic demo repository
              </label>
            )}
            <label>
              Untrusted evidence
              <textarea
                className="mono"
                rows={7}
                value={evidence}
                onChange={(e) => setEvidence(e.target.value)}
                placeholder="Paste documents, quotations or source code here. This channel cannot grant authority."
              />
            </label>
            <div className="upload-line">
              <label className="file-button">
                <Upload size={16} /> Attach files
                <input
                  aria-label="Attach evidence files"
                  type="file"
                  multiple
                  disabled={busy}
                  onChange={(e) => upload(e.target.files)}
                />
              </label>
              <span className="subtle">
                1 MB per file · inspected before release
              </span>
            </div>
            {attachments.length > 0 && (
              <div className="chips">
                {attachments.map((id) => (
                  <button
                    type="button"
                    key={id}
                    onClick={() =>
                      setAttachments((a) => a.filter((x) => x !== id))
                    }
                  >
                    {artifacts.find((a) => a.id === id)?.filename ||
                      "Attached artifact"}{" "}
                    <X size={12} />
                  </button>
                ))}
              </div>
            )}
            <div className="form-footer">
              <small>
                Synthetic / public data only. No real external email.
              </small>
              <button className="primary" disabled={busy}>
                {busy ? "Inspecting and working…" : "Run protected task"}
                <Play size={15} />
              </button>
            </div>
          </form>
          {result && (
            <section className="panel">
              <div className="panel-title">
                <h3>Agent response</h3>
                <Badge value={result.status} />
              </div>
              <div className="pillrow">
                <Badge value={result.provider} />
                <span className="subtle">
                  {result.model} · {result.seconds}s ·{" "}
                  {result.usage?.total_tokens ?? 0} tokens
                </span>
              </div>
              {result.error ? (
                <div className="notice error">{result.error}</div>
              ) : (
                <Output value={result.output} />
              )}
              <button
                className="text-button"
                onClick={() => go("Runtime Activity")}
              >
                Inspect runtime activity
              </button>
              {result.containment_probe && (
                <div className="notice">
                  Independent forced containment probe ·{" "}
                  {result.containment_probe.origin}:{" "}
                  {result.containment_probe.decision.error || "ALLOW"}.{" "}
                  {result.containment_probe.emails_executed} mock emails
                  executed. Separate from model proposals.
                </div>
              )}
              <h4>Tool activity</h4>
              {result.tool_activity.length ? (
                result.tool_activity.map((t: Row, i: number) => (
                  <div className="boundary-row" key={i}>
                    <span>{t.tool}</span>
                    <span className="subtle">
                      {t.destination || t.resource} · {t.result}
                    </span>
                  </div>
                ))
              ) : (
                <p className="subtle">
                  No external read tools used in this task.
                </p>
              )}
            </section>
          )}
        </div>
        <aside className="panel inspector">
          <div className="panel-title">
            <h3>Security inspector</h3>
            <ShieldCheck size={18} />
          </div>
          <div className="boundary-row">
            <span>Execution</span>
            <Badge value={health.isolation} />
          </div>
          <div className="boundary-row">
            <span>Memory</span>
            <Badge value="DISABLED" />
          </div>
          <div className="boundary-row">
            <span>Mock emails executed</span>
            <strong>{result?.emails_executed ?? 0}</strong>
          </div>
          <h4>Decision timeline</h4>
          {result ? (
            <div className="timeline">
              {result.decisions.map((d: Row, i: number) => (
                <div key={i}>
                  <span
                    className={"dot " + (d.result === "DENY" ? "warn" : "")}
                  />
                  <div>
                    <strong>{d.operation}</strong>
                    <small>{d.reason || d.result}</small>
                  </div>
                  <Badge value={d.result} />
                </div>
              ))}
            </div>
          ) : (
            <Empty text="Run a task to inspect actual broker decisions." />
          )}
          <h4>Evidence coverage</h4>
          {result?.artifacts.map((a: Row) => (
            <button
              className="source-button"
              key={a.id}
              onClick={() => {
                setInvestigate(a);
                go("Threat Intelligence");
              }}
            >
              <FileText size={15} />
              <span>
                {a.filename}
                <small>
                  {a.inspection_status} ·{" "}
                  {a.fragments.filter((f: Row) => f.signals.length).length}{" "}
                  threat fragments
                </small>
              </span>
              <ChevronRight size={14} />
            </button>
          ))}
        </aside>
      </div>
    </>
  );
}
