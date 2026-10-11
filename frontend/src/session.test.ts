import { strict as assert } from "node:assert";
import { APIError, AnonymousSession, requestOptions } from "./anonymousSession.ts";

const read = requestOptions();
const write = requestOptions({});
assert.equal(read.credentials, "same-origin");
assert.equal(write.credentials, "same-origin");
assert.equal(read.method, "GET");
assert.equal(write.method, "POST");
assert.equal(write.body, "{}");
assert.deepEqual(read.headers, {});
assert.deepEqual(write.headers, { "Content-Type": "application/json", "X-ATF-Demo": "1" });
assert(!JSON.stringify([read, write]).includes("Authorization"));

let created = 0, replaced = 0;
const initial = new AnonymousSession(async (path) => {
  if (path === "demo/session") created++;
  return { path };
}, () => replaced++);
await Promise.all(["agents", "overview", "runs"].map(path => initial.request(path)));
assert.equal(created, 1);
assert.equal(replaced, 0);

created = 0; replaced = 0;
const attempts: Record<string, number> = {};
const expiring = new AnonymousSession(async (path) => {
  if (path === "demo/session") { created++; return {}; }
  attempts[path] = (attempts[path] || 0) + 1;
  if (attempts[path] === 1) throw new APIError("DEMO_SESSION_REQUIRED");
  return { visitor: "replacement", path };
}, () => replaced++);
const refreshed = await Promise.all(["runs", "incidents", "artifacts"].map(path => expiring.request(path)));
assert.equal(created, 2, "Parallel expiry responses must create only one replacement");
assert.equal(replaced, 1, "Previously loaded visitor data must be cleared once");
assert.equal(expiring.revision, 1);
assert(refreshed.every(row => row.visitor === "replacement"));

let mutationAttempts = 0;
created = 0;
const mutating = new AnonymousSession(async (path) => {
  if (path === "demo/session") { created++; return {}; }
  mutationAttempts++; throw new APIError("DEMO_SESSION_REQUIRED");
}, () => {});
await assert.rejects(mutating.request("tasks", { artifact_ids: ["old-session-artifact"] }),
  (error: any) => error.code === "DEMO_SESSION_RECREATED");
assert.equal(mutationAttempts, 1, "Old-session mutations must never be replayed");
assert.equal(created, 2);

for (const code of ["DEMO_RATE_LIMITED", "DEMO_DAILY_BUDGET_EXHAUSTED", "DEMO_INFERENCE_DISABLED", "SESSION_CAPACITY_EXHAUSTED"]) {
  created = 0;
  const limited = new AnonymousSession(async (path) => {
    if (path === "demo/session") { created++; return {}; }
    throw new APIError(code);
  }, () => assert.fail("Quota failures must not replace the visitor session"));
  await assert.rejects(limited.request("tasks", {}), (error: any) => error.code === code);
  assert.equal(created, 1);
}

created = 0; let reads = 0;
const repeated = new AnonymousSession(async (path) => {
  if (path === "demo/session") { created++; return {}; }
  reads++; throw new APIError("DEMO_SESSION_REQUIRED");
}, () => {});
await assert.rejects(repeated.request("overview"), (error: any) => error.code === "DEMO_SESSION_REQUIRED");
assert.equal(created, 2); assert.equal(reads, 2, "Read recovery is bounded to one retry");

let releaseOld: ((value: any) => void) | undefined;
let oldReads = 0;
const overlapping = new AnonymousSession(async (path) => {
  if (path === "demo/session") return {};
  if (path === "old-result" && ++oldReads === 1) return new Promise(resolve => { releaseOld = resolve; });
  if (path === "expired" && overlapping.revision === 0) throw new APIError("DEMO_SESSION_REQUIRED");
  return { visitor: "new" };
}, () => {});
const delayed = overlapping.request("old-result");
await new Promise(resolve => setTimeout(resolve, 0));
await overlapping.request("expired");
releaseOld!({ visitor: "old" });
assert.equal((await delayed).visitor, "new", "A delayed old-visitor response must not repopulate cleared state");
console.log("Anonymous cookie transport, coalesced bootstrap, bounded recovery, stale-response suppression and quota handling passed");
