export function requestErrorMessage(code: unknown): string {
  const messages: Record<string, string> = {
    AUTHENTICATION_REQUIRED: "The access code was not accepted. Re-enter the current demo code.",
    BUSY_TRY_AGAIN: "The service is processing another request. Wait briefly and retry; you can select the same file again.",
    RATE_LIMITED: "The demo request limit was reached. Wait before retrying.",
    REQUEST_BUDGET_EXHAUSTED: "The demo request limit was reached. Wait before retrying.",
    INVALID_FIELDS_OR_LIMITS: "Check the task fields, supported inputs and file limits, then retry.",
    RUN_ACCESS_DENIED: "This run is unavailable. It may have expired, been removed by the temporary history limit, or belong to another session.",
    SESSION_ACCESS_DENIED: "This record is unavailable. It may have expired or belong to another session.",
    ARTIFACT_ACCESS_DENIED: "This artifact is unavailable. It may have expired or belong to another session.",
    INCIDENT_ACCESS_DENIED: "This incident is unavailable. Refresh the temporary records and select an available incident.",
    REQUEST_UNAVAILABLE: "The service is unavailable. It may be starting up; wait briefly and retry.",
  };
  if (typeof code !== "string" || !/^[A-Z][A-Z0-9_]{0,79}$/.test(code))
    return "The service returned an invalid response. Wait briefly and retry.";
  return messages[code] || `The request could not be completed (${code}). No successful result was released.`;
}
