import React from "react";
import { Upload, Search, FileText } from "lucide-react";
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
export function Scanner(props: ViewProps) {
  const {
    page,
    evidence,
    busy,
    upload,
    artifacts,
    setInvestigate,
    filter,
    setFilter,
    investigate,
    coverage,
  } = props;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">EVIDENCE BEFORE AUTHORITY</span>
          <h1>
            {page === "File Scanner" ? "Inspect a file" : "Threat intelligence"}
          </h1>
          <p className="subtle">
            Inspect source locations, released content and coverage gaps.
          </p>
        </div>
        <label className="primary file-button">
          <Upload size={16} /> Scan files
          <input
            aria-label="Scan files"
            type="file"
            multiple
            disabled={busy}
            onChange={(e) => upload(e.target.files)}
          />
        </label>
      </div>
      {busy && (
        <div className="notice">
          Inspection in progress. Verdicts will appear only after processing.
        </div>
      )}
      <div className="scan-grid">
        <section className="panel">
          <div className="panel-title">
            <h3>Artifact inventory</h3>
            <span className="subtle">{artifacts.length} records</span>
          </div>
          <div className="searchbox">
            <Search size={16} />
            <input
              aria-label="Search artifacts"
              placeholder="Filter by name or decision…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
          </div>
          {artifacts.length ? (
            artifacts
              .filter((a) =>
                (a.filename + " " + a.decision)
                  .toLowerCase()
                  .includes(filter.toLowerCase()),
              )
              .map((a) => (
                <button
                  key={a.id}
                  className={
                    "artifact-row " +
                    (investigate?.id === a.id ? "selected" : "")
                  }
                  onClick={() => setInvestigate(a)}
                >
                  <FileText size={20} />
                  <span>
                    <strong>{a.filename}</strong>
                    <small>
                      {a.inspection_status} · {a.fragments.length} fragments
                    </small>
                  </span>
                  <Badge value={a.decision} />
                </button>
              ))
          ) : (
            <Empty text="Upload or paste evidence to create an inspection record." />
          )}
        </section>
        {investigate ? (
          <ArtifactInspector record={investigate} />
        ) : (
          <section className="panel">
            <Empty text="Select an artifact to investigate its actual inspection." />
            <div className="coverage-list">
              {coverage.formats?.map((f: Row) => (
                <div key={f.format}>
                  <strong>{f.format}</strong>
                  <Badge value={f.status} />
                  <small>
                    {f.channels.join(", ") || "No adapter"}
                    <br />
                    Gaps: {f.gaps.join(", ")}
                  </small>
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </>
  );
}
