import React from "react";
import { Search } from "lucide-react";
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
export function EventLog(props: ViewProps) {
  const { page, filter, setFilter, events } = props;
  return (
    <>
      <div className="page-heading">
        <div>
          <span className="eyebrow">OBSERVABLE ENFORCEMENT</span>
          <h1>Security events</h1>
          <p className="subtle">
            Recorded decisions across inspection, model context and execution
            boundaries.
          </p>
        </div>
        <span className="subtle">{events.length} retained records</span>
      </div>
      <section className="panel">
        <div className="searchbox">
          <Search size={16} />
          <input
            aria-label="Search security events"
            placeholder="Filter operations, decisions or reasons…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <EventTable rows={events} filter={filter} />
      </section>
    </>
  );
}
