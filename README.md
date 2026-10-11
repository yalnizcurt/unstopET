# Agent Trust Firewall

Runtime security for AI agents: a React/TypeScript security console, shared inspection engine, hosted protected runtime and reusable Python client. Server policy controls authority, evidence release and external effects even when the model follows an adversarial instruction.

- Console: https://agent-trust-firewall.vercel.app
- Public read-only walkthrough: https://agent-trust-firewall.vercel.app/#Walkthrough
- API documentation: https://agent-trust-firewall-api.onrender.com/api/docs
- API health: https://agent-trust-firewall-api.onrender.com/api/v1/health
- Repository: https://github.com/yalnizcurt/unstopET

The console centers on Protected Agents, Runtime Activity, Security Incidents, read-only Security Policies, Security Lab, Integrations and Settings. Existing file scanning, workspaces, fragment investigation and A/B/C evaluations remain accessible. Access is public with no login or access code. The console opens directly to Security Overview and transparently establishes an isolated anonymous server session. No Groq key enters the frontend.

Agents: procurement comparison; public HTTPS research through a controlled reader; synthetic repository review with inert patch suggestions. All generation uses the existing verified Linux runtime, trusted Model Gateway and mandatory broker. Mock email requests cannot independently authorize side effects; live email is disabled.

Supported declared adapters: UTF-8 text, static HTML, PDF text/metadata/annotation strings, DOCX XML channels, XLSX cells/hidden sheets/comments, bounded ZIPs. English raster OCR and metadata remain partial; QR decoding and guaranteed recognition are not enabled. Unsupported regions remain withheld. Persistent memory and unrestricted shell/connectors are disabled.

The integration-first prototype adds a real independent SDK application, bounded brokered tool steps and source-linked runtime investigations. The final package is in [submission](submission/README.md); prior measurements retain their original versions in [Platform release](docs/PLATFORM_RELEASE.md) and [the historical checklist](docs/RELEASE_CHECKLIST.md).

**Detection reliability is an open gap.** A frozen first-use challenge detected 4/48 attacks and falsely flagged 6/16 benign cases in both deterministic and routed-AI configurations. Public tool-output attacks were 0/32 detected. These results are separate from passing containment checks and successful business workflows. Read [the complete challenge](evaluation/heldout/README.md); no universal protection, enterprise readiness or official F3/D2 achievement is claimed.

## Local development

The backend requires Linux Landlock ABI 3+ and libseccomp; it deliberately fails closed on unsupported hosts. Use the Docker image on a supported Linux kernel. Set `GROQ_API_KEY`, `GROQ_MODEL`, `ALLOWED_ORIGINS` and optionally `SEMANTIC_ENABLED=1` in the trusted server environment. Application access no longer depends on `APP_ACCESS_TOKEN`. Configure the public-demo request/operation caps and inference-disable switch as described in [Deployment](DEPLOYMENT.md). Never place secrets in frontend variables or Git.

```sh
docker build -t agent-trust-firewall .
docker run --rm agent-trust-firewall python3 acceptance.py
# For a Linux development service, provide secrets through your existing secret manager.
cd frontend
npm ci
npm run dev
npm run build
```

The production start command is `python3 api.py`. Versioned APIs live under `/api/v1`; request schemas reject browser-supplied security authority. Local development can use `VITE_API_BASE`. The production console pins API calls to its own origin; Vercel forwards `/api` only to the existing Render service with private/no-store response headers. No browser parameter can choose another API destination.

## Verification and limits

The pre-public-access Linux acceptance report records 120 passing checks, zero failures/errors and two Mac-only skips; anonymous-session release checks are reported separately. The earlier 168-instance authored benchmark detects 66/84 attack instances with 0/84 benign flags; its 28 strings are repeated over six formats. Real Prompt Guard calibration and the 8a412ab hosted comparison show a small familiar-example detection gain, which did not generalize to the first-use challenge. Historical A–G evidence remains in [submission-readiness-report.json](submission-readiness-report.json); the 8a412ab workflows and 30 A/B/C responses remain in [integration-platform-production-report.json](integration-platform-production-report.json). Final exact-source evidence is indexed in [the submission checklist](submission/FINAL_CHECKLIST.md).

Each visitor receives a server-issued, 24-hour `Secure`/`HttpOnly`/`SameSite=Strict` cookie. Artifacts, runs and incidents are scoped to that anonymous session; browser-supplied identities cannot claim another visitor’s data. Free Render history is temporary SQLite, bounded to 24 hours / 300 total records. Raw binaries are discarded after extraction. Synthetic/public demo inputs only; this is not enterprise tenant authentication or durable production audit storage. Free services can sleep and restart, expiring sessions, history and application abuse counters. Provider-account limits remain authoritative.

See [Implementation sequence](IMPLEMENTATION.md), [Architecture](ARCHITECTURE.md), [Security](SECURITY.md), [Agent capabilities](AGENTS.md), [Coverage](COVERAGE.md), [Evaluation](EVALUATION.md), [Deployment](DEPLOYMENT.md), [Submission package](SUBMISSION.md), [Release checklist](docs/RELEASE_CHECKLIST.md) and [Implementation audit](docs/IMPLEMENTATION_AUDIT.md).

## Integration-first transformation

The dedicated implementation branch extends the same broker into maximum three model turns / two model-selected tool requests. Tools include released reads, deterministic supplier scoring and inert patch receipts; no direct child network/model/filesystem/shell/MCP path is enabled. Server-issued snapshots and inspection precede every continuation. Failed runs retain chronological evidence.

Use the [Python client](sdk/python/README.md) and [independent reference application](examples/external_procurement_client/README.md) for hosted protected execution. Inspection alone does not enforce your external agent. Source-bound registry verification is distinct from connectivity. See [transformation tracking](docs/PLATFORM_TRANSFORMATION.md), [category crosswalk](docs/OFFICIAL_CATEGORY_CROSSWALK.md) and [platform walkthrough](docs/PLATFORM_DEMO.md). Production verification for each new release is reported separately from historical submission evidence. Earlier access-token reports and videos retain their historical source and are not proof of current anonymous access.

## Public demo access and budgets

Visitors can inspect synthetic/public files and run all three existing protected profiles without login, subject to server-side session/IP request limits, upload/file-count limits, a global admitted-operation cap, concurrency control and the existing runtime/model budgets. An application operation cap is not a measured USD or token budget. When inference is disabled or the cap is exhausted, non-inference exploration remains available; no fabricated AI success replaces an error. Anonymous visitor isolation is temporary demonstration storage, not durable personal accounts or enterprise tenancy.

The Python SDK establishes its own session lazily and retains the server cookie within one client instance. Use `ATFClient(base_url)`; the legacy `api_key` argument is accepted for source compatibility but ignored and never transmitted. A different browser or SDK instance cannot see that client’s records. See [SDK migration and errors](sdk/python/README.md) and [the API session contract](docs/API_INTEGRATION.md).
