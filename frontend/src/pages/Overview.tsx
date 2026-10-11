import React from "react";
import {
  ShieldCheck,
  ArrowUpRight,
  LockKeyhole,
  Check,
  ShieldAlert,
  Clock3,
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
export function Overview(props: ViewProps) {
  const { page, overview, go, health, settings, agent, events } = props;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">YOUR AGENT SECURITY POSTURE</span>
          <h1>Security overview</h1>
          <p className="subtle">
            Your isolated temporary workspace. No login required. Archived lab
            measurements keep their original timestamps.
          </p>
        </div>
        <button className="primary" onClick={() => go("Agents")}>
          Launch an agent
          <ArrowUpRight size={17} />
        </button>
      </div>
      <div className="integration-summary">
        <span>
          <strong>{overview.protected_agents ?? "—"}</strong> protected profiles
        </span>
        <span>
          <strong>{overview.verified_integrations ?? "—"}</strong> verified
          integrations
        </span>
        <span>
          <strong>{overview.unverified_integrations ?? "—"}</strong> unverified
          integrations
        </span>
        <span>
          <strong>{overview.sanitized ?? "—"}</strong> sanitized fragments
        </span>
        <span>
          <strong>{overview.partial ?? "—"}</strong> incomplete inspections
        </span>
      </div>
      <div className="stats">
        {[
          ["Inspected inputs", overview.inputs, FileText],
          ["Threat fragments", overview.threats, ShieldAlert],
          ["Blocked actions", overview.blocked_actions, LockKeyhole],
          ["Completed runs", overview.completed, Check],
        ].map(([label, value, Icon]: any) => (
          <div className="stat" key={label}>
            <div>
              <span>{label}</span>
              <Icon size={18} />
            </div>
            <strong>{value ?? "—"}</strong>
            <small>
              {label === "Threat fragments"
                ? "Observed detector signals"
                : label === "Blocked actions"
                  ? "Broker denials, including forced tests"
                  : label === "Completed runs"
                    ? "Output released; utility scored separately"
                  : "Stored demo activity"}
            </small>
          </div>
        ))}
      </div>
      <div className="overview-grid">
        <section className="panel">
          <div className="panel-title">
            <h3>Threat distribution</h3>
            <span className="subtle">Observed categories</span>
          </div>
          {Object.keys(overview.category_counts || {}).length ? (
            Object.entries(overview.category_counts).map(
              ([cat, count]: any) => (
                <div className="bar-row" key={cat}>
                  <span>{cat.replaceAll("_", " ")}</span>
                  <div>
                    <i
                      style={{
                        width:
                          Math.max(
                            3,
                            (Number(count) /
                              Math.max(
                                ...Object.values(overview.category_counts).map(
                                  Number,
                                ),
                              )) *
                              100,
                          ) + "%",
                      }}
                    />
                  </div>
                  <b>{count}</b>
                </div>
              ),
            )
          ) : (
            <Empty text="Run a scan or agent task to record detection signals." />
          )}
        </section>
        <section className="panel">
          <div className="panel-title">
            <h3>Execution boundaries</h3>
            <ShieldCheck size={18} />
          </div>
          {[
            ["Agent runtime", health.isolation],
            ["Model generation", settings.model],
            ["Semantic inspection", health.semantic_detector],
            ["Persistent memory", "DISABLED"],
          ].map(([label, value]) => (
            <div className="boundary-row" key={label}>
              <span>{label}</span>
              <span className="subtle mono">{value}</span>
            </div>
          ))}
          <div className="mini-stats">
            <div>
              <strong>{overview.total_tokens ?? 0}</strong>
              <small>Generation tokens</small>
            </div>
            <div>
              <strong>{overview.avg_seconds ?? "—"}</strong>
              <small>Mean task seconds</small>
            </div>
            <div>
              <strong>{overview.partial ?? "—"}</strong>
              <small>Partial scans</small>
            </div>
          </div>
        </section>
      </div>
      <section className="panel">
        <div className="panel-title">
          <h3>Recent security events</h3>
          <button
            className="text-button"
            onClick={() => go("Security Incidents")}
          >
            View all
            <ArrowUpRight size={15} />
          </button>
        </div>
        <EventTable rows={overview.events || []} />
      </section>
      <div className="notice subtle-notice">
        <Clock3 size={16} />
        {overview.retention}
      </div>
    </>
  );
}
