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
export function EventTable({
  rows,
  filter = "",
}: {
  rows: Row[];
  filter?: string;
}) {
  const matches = rows.filter((e) =>
    JSON.stringify(e).toLowerCase().includes(filter.toLowerCase()),
  );
  return matches.length ? (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Boundary / operation</th>
            <th>Decision</th>
            <th>Reason / signal</th>
          </tr>
        </thead>
        <tbody>
          {matches.map((e) => (
            <tr key={e.id}>
              <td className="subtle">
                {new Date(e.created_at).toLocaleTimeString()}
              </td>
              <td>{e.operation}</td>
              <td>
                <Badge value={e.result} />
              </td>
              <td className="subtle">
                {e.reason ||
                  e.signals?.map((s: Row) => s.category).join(", ") ||
                  "—"}
                {e.origin && <small>{e.origin.replaceAll("_", " ")}</small>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  ) : (
    <Empty text="No matching security events." />
  );
}
