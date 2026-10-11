import React from "react";
import {
  ShieldCheck,
  Bot,
  ChevronRight,
  Globe,
  Code2,
  BriefcaseBusiness,
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
export function ProtectedAgents(props: ViewProps) {
  const {
    integrations,
    details,
    page,
    go,
    agents,
    sessions,
    choose,
    setIntent,
    setUrls,
    setRepo,
    setAttachments,
    setResult,
    agent,
    intent,
    artifacts,
    filter,
  } = props;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">SHARED SECURITY. DISTINCT TASKS.</span>
          <h1>Protected agents</h1>
          <p className="subtle">
            Three registered reference integrations, one enforced security
            engine.
          </p>
        </div>
        <button className="primary" onClick={() => go("Integrations")}>
          Protect an agent
        </button>
      </div>
      <div className="agent-grid">
        {agents.map((a) => (
          <article className="panel agent-card" key={a.id}>
            <div className="agent-icon">
              {a.id === "procurement" ? (
                <BriefcaseBusiness />
              ) : a.id === "research" ? (
                <Globe />
              ) : (
                <Code2 />
              )}
            </div>
            <Badge
              value={
                integrations.find((i: Row) => i.id === a.id)
                  ?.lifecycle_status || "UNKNOWN"
              }
            />
            <h2>{a.name}</h2>
            <small>
              HOSTED PROTECTED RUNTIME ·{" "}
              {integrations.find((i: Row) => i.id === a.id)?.policy_profile}
            </small>
            <p className="subtle">{a.description}</p>
            <div className="chips">
              {a.tools.map((t: string) => (
                <span key={t}>{t.replaceAll("_", " ")}</span>
              ))}
            </div>
            <p className="subtle">
              Verified boundaries:{" "}
              {integrations.find((i: Row) => i.id === a.id)
                ?.verified_security_boundaries.length ?? 0}{" "}
              /{" "}
              {integrations.find((i: Row) => i.id === a.id)
                ?.required_security_boundaries.length ?? 0}
            </p>
            <button className="text-button" onClick={() => details(a.id)}>
              Security details
            </button>
            <div className="card-bottom">
              <span className="subtle">
                <ShieldCheck size={14} /> Shared broker enforced
              </span>
              <button className="primary" onClick={() => choose(a.id)}>
                Open workspace
                <ChevronRight size={16} />
              </button>
            </div>
          </article>
        ))}
      </div>
      <section className="panel">
        <div className="panel-title">
          <h3>Recent task history</h3>
        </div>
        {sessions.length ? (
          <div className="history">
            {sessions.map((s) => (
              <button
                key={s.id}
                onClick={() => {
                  choose(s.agent_id);
                  setIntent(s.intent);
                  setUrls(
                    s.tool_activity
                      .filter((t: Row) => t.tool === "public_https_read")
                      .map((t: Row) => t.destination)
                      .join("\n"),
                  );
                  setRepo(
                    s.tool_activity.some(
                      (t: Row) => t.tool === "synthetic_repo_read",
                    ),
                  );
                  setAttachments(
                    s.artifacts
                      .filter(
                        (a: Row) =>
                          a.source_kind === "USER_SUPPLIED_UNTRUSTED_CONTENT",
                      )
                      .map((a: Row) => a.id),
                  );
                  setResult(s);
                }}
              >
                <Bot size={18} />
                <span>
                  <strong>
                    {agents.find((a) => a.id === s.agent_id)?.name}
                  </strong>
                  <small>{s.intent}</small>
                </span>
                <Badge value={s.status} />
                <ChevronRight size={16} />
              </button>
            ))}
          </div>
        ) : (
          <Empty text="Complete a task to start your history." />
        )}
      </section>
    </>
  );
}
