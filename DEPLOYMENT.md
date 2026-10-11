# Vercel + Render deployment

Repository: https://github.com/yalnizcurt/unstopET

## Existing production projects

- Interface: https://agent-trust-firewall.vercel.app
- API: https://agent-trust-firewall-api.onrender.com
- Interactive API documentation: https://agent-trust-firewall-api.onrender.com/api/docs
- Render service: https://dashboard.render.com/web/srv-db3v5p3l550s73c220d0
- Region/plan: Singapore/free.

Use these existing projects and URLs. The application opens directly to Security Overview without login, an access code or a registration screen. It transparently establishes an isolated anonymous server session. The Groq key remains in Render server secrets; no provider/deployment credential belongs in the browser, SDK client, Vercel variables or source.

## Render configuration

The existing `render.yaml` selects the Docker service and `python3 api.py`. Keep `GROQ_API_KEY`, `GROQ_MODEL`, `ALLOWED_ORIGINS` and the existing optional semantic/provider settings in the trusted server environment. `APP_ACCESS_TOKEN` no longer authorizes application requests and is not required by the API. Remove obsolete application-token configuration without changing the server-side Groq key or deployment credentials.

`ALLOWED_ORIGINS` contains exact approved browser origins, including `https://agent-trust-firewall.vercel.app`; never use `*`. The session cookie is host-only `__Host-atf-demo`, Secure, HttpOnly, SameSite=Strict, Path=/ and Max-Age=86400. The server stores a hashed lookup of a random 256-bit identity and returns no identity in JSON. Production requires HTTPS; do not disable Secure or TLS verification to make development requests pass.

Configure the public-demo session/IP request limits, global operation concurrency, daily admitted-operation cap and inference-disable switch using the deployment variables documented in `render.yaml`. The operation cap counts admitted mutating inspection/task/evaluation jobs, not actual USD spend or provider token usage. Session/IP counters and the daily application cap use temporary single-instance storage and reset on free-service restart/redeploy. Provider-account quotas remain authoritative. Use synthetic/public demonstration data only.

| Variable | Default | Enforced scope |
|---|---:|---|
| `DEMO_SESSION_REQUESTS_PER_MINUTE` | 120 | Requests for one anonymous visitor |
| `DEMO_IP_REQUESTS_PER_MINUTE` | 300 | Requests for the hashed observed connection peer |
| `DEMO_SESSION_WRITES_PER_HOUR` | 20 | Mutations for one visitor |
| `DEMO_IP_WRITES_PER_HOUR` | 100 | Mutations for the observed peer |
| `DEMO_SESSION_CREATES_PER_HOUR` | 20 | New visitors per observed peer |
| `DEMO_DAILY_OPERATIONS` | 100 | Admitted inspections, tasks and evaluations across the service |
| `DEMO_SESSIONS_MAX` | 256 | Retained anonymous visitors |
| `DEMO_INFERENCE_ENABLED` | `1` | Set `0` to reject new admitted operations while keeping reads available |

Concurrency is one admitted mutating job. Daily application operations reset at UTC midnight or when temporary deployment storage is lost. Forwarded IP headers are not trusted identities; shared proxy peers can aggregate otherwise separate visitors and hit the same additional IP cap. Session ownership still comes only from the server-issued cookie.

Startup runs an actual synthetic compromised child and positive-control containment tests before using credentials or accepting application work. It verifies filesystem, credentials, networking, shell and alternate connector denial while completing a legitimate brokered task. Missing Landlock ABI 3+ or seccomp fails closed. Never substitute unrestricted execution to make a deploy succeed. Confirm `/api/v1/health` reports `READY` and `VERIFIED_LINUX`, and correlate the served source with Linux acceptance evidence.

The image runs as a non-root user and uses Render's `PORT`. No new database, queue, disk, project, paid plan or microservice is needed for this prototype.

## Vercel configuration

Keep the existing project's Root Directory `frontend`, Vite framework, build command `npm run build` and output directory `dist`. The console pins API calls to its own origin; the fixed `/api` rewrite reaches only the existing Render service. No browser parameter may select another API destination. Responses remain private/no-store, and cookies must survive this same-origin proxy.

Open the site directly. No secret lookup or code entry is needed. The frontend establishes the anonymous session with `POST /api/v1/demo/session`, JSON `{}` and `X-ATF-Demo: 1`, then sends the retained HttpOnly cookie with application requests. Mutations retain the header. Exact browser Origin checks and the custom header are CSRF controls, not identity or agent authority. Administrative/internal routes are outside the public-demo allowlist.

The Python SDK may call Render directly over HTTPS. One `ATFClient` instance retains its own cookie in memory; another instance and the browser are separate visitors. `ATFClient(base_url, api_key=None)` retains source compatibility, but the legacy argument is ignored and no bearer token is transmitted. See [SDK migration](sdk/python/README.md).

## Verify this release before declaring it complete

- A fresh browser opens Security Overview with no login, access-code field, sign-out action or hidden protected-workspace gate. Check desktop and mobile.
- Bootstrap through Vercel sets the host-only Secure/HttpOnly/SameSite=Strict cookie. Missing, unknown or expired session returns `DEMO_SESSION_REQUIRED` (401) on session-owned routes; bootstrap replaces it with a fresh empty visitor.
- Two independent visitors cannot read each other's artifact, task, run, incident or fresh evaluation records, including guessed IDs and forged owner fields.
- Cross-site/unapproved Origin requests and missing mutation headers fail before application work. Neither accepted Origin nor a browser identity field grants permissions.
- Session/IP quotas and global operation/concurrency limits produce explicit responses. `DEMO_RATE_LIMITED`, `DEMO_DAILY_BUDGET_EXHAUSTED` and `DEMO_INFERENCE_DISABLED` return 429. Non-inference exploration remains available when new inference is disabled.
- Real anonymous Procurement, Research and Developer workflows use Groq and the isolated runtime. Source inspection, bounded tools, current snapshots, output DLP and independent unauthorized-tool denial remain enforced. Generated inert patches are not executed or automatically verified.
- Forged model roles, system prompts, trust labels, grants and stale permits remain rejected; unsupported/partial channels stay withheld and do not become whole-file SAFE claims.
- Repeat the full Linux acceptance suite, frontend tests/build, SDK tests and exact-source hosted checks. Preserve provider failures and unknown outcomes rather than report fabricated success.

## Temporary data and budgets

Live SQLite history is intentionally temporary at `/tmp/atf-history.sqlite3`, capped at 24 hours / 300 total records, with at most 100 records returned per kind in a list. Reads prune expired records; restart/redeploy loses visitor history and sessions. Raw uploaded bytes are discarded after extraction. These are isolated temporary visitors, not durable accounts, enterprise tenancy or production audit storage.

Committed public evaluation archives retain original source versions, timestamps and scopes; they contain synthetic/public fixtures and are explicitly labelled archived. They do not turn live history into durable storage or demonstrate current anonymous-session behavior. Free Render sleep/cold starts and provider-account quotas can affect demonstration availability. No universal protection or official F3/D2 achievement is established by a smoke pass.

## Historical release evidence

Prior reports remain unchanged: [Gate1 deployment](cloud-deployment-report.json), [platform smoke](cloud-platform-smoke-report.json), [historical A–G release](submission-readiness-report.json), [integration-platform comparison](integration-platform-production-report.json) and [historical checklist](docs/RELEASE_CHECKLIST.md). Their shared-access-token tests, browser captures and videos describe the original source versions. They are not current access instructions or evidence of anonymous isolation. New deployment verification must identify the exact public-access backend and frontend commits separately.
