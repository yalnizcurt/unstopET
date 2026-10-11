import React from "react";
import { Activity } from "lucide-react";
export type Row = Record<string, any>;
export type ViewProps = Record<string, any> & {
  urls: string;
  attachments: string[];
  agents: Row[];
  sessions: Row[];
  artifacts: Row[];
  evaluations: Row[];
  setAttachments: React.Dispatch<React.SetStateAction<string[]>>;
};
export function Badge({ value }: { value: any }) {
  const s = String(value ?? "UNKNOWN");
  return (
    <span
      className={
        "badge " +
        (/DENY|BLOCK|UNSUPPORTED|FAILED|SANITIZE|INCOMPLETE|PARTIAL|REVIEW|DEGRADED/.test(s)
          ? "amber"
          : /UNKNOWN|UNVERIFIED|DISABLED|NOT_VERIFIED/.test(s)
            ? "muted"
            : /ALLOW|COMPLETE|READY|VERIFIED|ENABLED/.test(s)
            ? "green"
            : "muted")
      }
    >
      {s.replaceAll("_", " ")}
    </span>
  );
}
export function Empty({
  text = "No recorded activity yet.",
}: {
  text?: string;
}) {
  return (
    <div className="empty">
      <Activity size={25} />
      <p>{text}</p>
    </div>
  );
}
export function Output({ value }: { value: string }) {
  const lines = value.split("\n");
  const table = lines.filter(
    (l) => l.trim().startsWith("|") && !/^\s*\|[\s:|\-]+$/.test(l),
  );
  return (
    <div className="response">
      <pre>{lines.filter((l) => !l.trim().startsWith("|")).join("\n")}</pre>
      {table.length > 0 && (
        <div className="table-scroll">
          <table>
            <tbody>
              {table.map((l, i) => (
                <tr key={i}>
                  {l
                    .split("|")
                    .slice(1, -1)
                    .map((c, j) =>
                      i === 0 ? (
                        <th key={j}>{c.trim()}</th>
                      ) : (
                        <td key={j}>{c.trim()}</td>
                      ),
                    )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
