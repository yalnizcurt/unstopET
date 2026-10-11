import React from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  Bot,
  Radar,
  FileSearch,
  FlaskConical,
  Activity,
  SlidersHorizontal,
  ChartColumn,
  Settings,
  ChevronRight,
  ArrowUpRight,
  LockKeyhole,
  Upload,
  Play,
  RefreshCw,
  Search,
  Check,
  AlertTriangle,
  Globe,
  Code2,
  BriefcaseBusiness,
  Menu,
  X,
  Sun,
  Moon,
  LogOut,
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
import { childInventory } from "../inventory";
export function ArtifactInspector({ record }: { record: Row }) {
  return (
    <div className="panel investigation">
      <div className="panel-title">
        <div>
          <span className="eyebrow">ARTIFACT INVESTIGATION</span>
          <h3>{record.filename}</h3>
        </div>
        <Badge value={record.decision} />
      </div>
      <div className="pillrow">
        <Badge value={record.inspection_status} />
        <span className="subtle">{record.release_scope}</span>
      </div>
      <p className="subtle">Coverage applies to declared parser channels. COMPLETE is not a claim that every possible document feature was inspected or is safe.</p>
      <p className="subtle">
        Detected type: {record.media_type} · profile: {record.parser_version}
      </p>
      <p className="subtle mono hash">SHA-256 {record.sha256}</p>
      {record.context_source_id && (
        <p className="subtle mono hash">
          Model source reference: {record.context_source_id}
        </p>
      )}
      <p className="subtle">
        Inspected:{" "}
        {record.inspected_channels.join(", ") || "No extracted channels"}
      </p>
      {record.uninspected_channels.length > 0 && (
        <div className="notice">
          <AlertTriangle size={16} />
          <span>
            Withheld / incomplete: {record.uninspected_channels.join(", ")}
          </span>
        </div>
      )}
      {record.children?.length > 0 && (
        <details>
          <summary>Embedded file inventory</summary>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Source path</th>
                  <th>Declared coverage</th>
                  <th>Withheld channels</th>
                </tr>
              </thead>
              <tbody>
                {childInventory(record.children).map((c: Row) => (
                  <tr key={c.id}>
                    <td>{c.path}</td>
                    <td>
                      <Badge value={c.status} />
                    </td>
                    <td>{c.gaps.join(", ") || "None in declared profile"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
      {record.fragments.map((f: Row) => (
        <details key={f.id} className="fragment" open={!!f.signals.length}>
          <summary>
            <span className="mono">{f.location}</span>
            <Badge value={f.disposition} />
          </summary>
          {f.signals.length > 0 && (
            <p className="signal">
              {f.signals
                .map(
                  (s: Row) =>
                    s.category +
                    " · " +
                    s.engine +
                    " · " +
                    (s.engine === "prompt_guard_2"
                      ? "raw score " + Number(s.confidence).toFixed(4)
                      : "rule match"),
                )
                .join(" / ")}
            </p>
          )}
          <div className="diff">
            <div>
              <span className="eyebrow">ORIGINAL · INERT TEXT</span>
              <pre>{f.original_text}</pre>
            </div>
            <div>
              <span className="eyebrow">RELEASED EVIDENCE</span>
              <pre>{f.text}</pre>
            </div>
          </div>
          <small>
            {f.router}
            {f.routing &&
              " · " +
                f.routing.reason +
                " · completed: " +
                String(f.routing.analysis_complete)}
          </small>
        </details>
      ))}
      <p className="subtle">
        {record.note} No whole-file SAFE claim. Detector scores and risk bands
        are uncalibrated signals.
      </p>
    </div>
  );
}
