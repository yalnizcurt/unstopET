import { requestErrorMessage } from "./errors.ts";

export class APIError extends Error {
  readonly code: string;
  constructor(code: unknown) {
    const safe = typeof code === "string" && /^[A-Z][A-Z0-9_]{0,79}$/.test(code)
      ? code : "INVALID_SERVICE_RESPONSE";
    super(requestErrorMessage(safe));
    this.code = safe;
  }
}

export function requestOptions(body?: Record<string, unknown>): RequestInit {
  return {
    method: body === undefined ? "GET" : "POST",
    credentials: "same-origin",
    headers: body === undefined ? {} : { "Content-Type": "application/json", "X-ATF-Demo": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  };
}

type Transport = (path: string, body?: Record<string, any>) => Promise<any>;

// The browser never receives or chooses its session identity. Concurrent expiry
// responses share one replacement, and old-session mutations are not replayed.
export class AnonymousSession {
  private valid = false;
  private generation = 0;
  private pending: Promise<void> | null = null;
  private transport: Transport;
  private onReplacement: () => void;
  constructor(transport: Transport, onReplacement: () => void) {
    this.transport = transport; this.onReplacement = onReplacement;
  }
  get revision(): number { return this.generation; }

  async establish(): Promise<void> {
    if (this.valid) return;
    if (!this.pending) {
      this.pending = this.transport("demo/session", {}).then(() => {
        this.valid = true;
      }).finally(() => { this.pending = null; });
    }
    return this.pending;
  }

  async request(path: string, body?: Record<string, any>): Promise<any> {
    await this.establish();
    const generation = this.generation;
    let result: any;
    let expired = false;
    try {
      result = await this.transport(path, body);
    } catch (error) {
      if (!(error instanceof APIError) || error.code !== "DEMO_SESSION_REQUIRED") throw error;
      expired = true;
    }
    if (!expired && generation === this.generation) return result;
    if (expired && this.generation === generation) {
      this.valid = false;
      this.generation++;
      this.onReplacement();
    }
    await this.establish();
    if (body !== undefined) throw new APIError("DEMO_SESSION_RECREATED");
    // A second expiry is an explicit failure, never an unbounded retry loop.
    try { return await this.transport(path); }
    catch (retryError) {
      if (retryError instanceof APIError && retryError.code === "DEMO_SESSION_REQUIRED") this.valid = false;
      throw retryError;
    }
  }
}
