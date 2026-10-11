export function routeFromHash(hash: string): string {
  try {
    const raw = decodeURIComponent(hash.slice(1)) || "Overview";
    const route =
      (
        {
          Agents: "Protected Agents",
          Policies: "Security Policies",
          "Security Events": "Event Log",
        } as Record<string, string>
      )[raw] || raw;
    return [
      "Protected Agents",
      "Runtime Activity",
      "Security Incidents",
      "Security Policies",
      "Security Lab",
      "Integrations",
      "Agent Details",
      "Event Log",
      "Overview",
      "Threat Intelligence",
      "File Scanner",
      "Attack Lab",
      "Security Events",
      "Policies",
      "Evaluations",
      "Settings",
      "Workspace",
    ].includes(route)
      ? route
      : "Overview";
  } catch {
    return "Overview";
  }
}
