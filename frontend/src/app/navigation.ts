import {
  LayoutDashboard,
  Bot,
  Activity,
  ShieldAlert,
  SlidersHorizontal,
  FlaskConical,
  Plug,
  Settings,
} from "lucide-react";
export const nav = [
  ["Overview", LayoutDashboard],
  ["Protected Agents", Bot],
  ["Runtime Activity", Activity],
  ["Security Incidents", ShieldAlert],
  ["Security Policies", SlidersHorizontal],
  ["Security Lab", FlaskConical],
  ["Integrations", Plug],
  ["Settings", Settings],
] as const;
export function parentRoute(page: string) {
  if (["Workspace", "Agent Details"].includes(page)) return "Protected Agents";
  if (
    [
      "Attack Lab",
      "Evaluations",
      "File Scanner",
      "Threat Intelligence",
    ].includes(page)
  )
    return "Security Lab";
  if (page === "Event Log") return "Security Incidents";
  return page;
}
