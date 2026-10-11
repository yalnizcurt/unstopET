import type { Row } from "../components/Common";
import { APIError, requestOptions } from "../anonymousSession";
export const API = location.origin;
export async function request(path: string, body?: Row) {
  let response: Response;
  try {
    response = await fetch(API + "/api/v1/" + path, {
      ...requestOptions(body), signal: AbortSignal.timeout(150000),
    });
  } catch { throw new APIError("REQUEST_UNAVAILABLE"); }
  let data;
  try { data = await response.json(); }
  catch { throw new APIError("INVALID_SERVICE_RESPONSE"); }
  if (!response.ok) throw new APIError(data?.error);
  return data;
}
