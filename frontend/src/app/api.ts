import type { Row } from "../components/Common";
export const API =
  (import.meta as any).env.VITE_API_BASE ||
  "https://agent-trust-firewall-api.onrender.com";
export async function request(path: string, token: string, body?: Row) {
  const response = await fetch(API + "/api/v1/" + path, {
    method: body ? "POST" : "GET",
    headers: {
      Authorization: "Bearer " + token,
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(150000),
  });
  const data = await response.json();
  if (!response.ok) throw Error(data.error || "Service unavailable");
  return data;
}
