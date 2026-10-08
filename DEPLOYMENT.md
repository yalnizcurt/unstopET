# Vercel + Render deployment

Repository: https://github.com/yalnizcurt/unstopET

## Current deployment

- Interface: https://agent-trust-firewall.vercel.app
- API: https://agent-trust-firewall-api.onrender.com
- Interactive API documentation: https://agent-trust-firewall-api.onrender.com/api/docs
- Render service: https://dashboard.render.com/web/srv-db3v5p3l550s73c220d0
- Region/plan: Singapore/free; deploy after repository checks pass.
- Historical Gate 1 verification: [cloud-deployment-report.json](cloud-deployment-report.json); platform verification is recorded separately in [cloud-platform-smoke-report.json](cloud-platform-smoke-report.json).

The existing Render connection and Vercel login were used. The hosted browser completed an actual Groq task after the Render startup isolation test passed. The Groq key was stored in Render with explicit user approval; it is absent from source and frontend. For access, copy `APP_ACCESS_TOKEN` from the Render service's Environment page into the interface's access-code field. The interface never saves it.

## Render API

1. Sign in to an existing Render account and create a Blueprint from this repository's `main` branch. `render.yaml` selects a free Docker web service.
2. Set `GROQ_API_KEY` as a server environment secret. Do not add it to Git, a frontend field, a Docker build argument or browser storage.
3. Keep the generated `APP_ACCESS_TOKEN`. This shared demo access code authorizes paid model calls; disclose it only to demo users.
4. Set `ALLOWED_ORIGINS` to the exact Vercel production origin, such as `https://your-project.vercel.app`. Multiple exact origins can be comma-separated. Do not use `*`.
5. Deploy and inspect startup logs. Success is `Linux isolation verified; authenticated API ready.` Confirm `/api/health` reports `READY` and `VERIFIED_LINUX`.

Startup launches a synthetic-only compromised child and tests filesystem, parent credentials, networking, shell execution and alternate connectors. It also completes a legitimate brokered task. The container requires Landlock ABI 3+ and usable seccomp; the current Render deployment passed these checks. Each later startup must repeat them. If its security policy/kernel disallows these controls, the service stays unavailable. Do not remove restrictions or substitute an unrestricted child to get a successful deploy.

The Docker image runs as a non-root user and binds Render's `PORT`. The application verifies boundaries before reading the provider key or opening the HTTP listener. No storage disk, queue, second microservice or paid service is required for this slice.

## Vercel interface

1. Import this repository into Vercel.
2. Set **Root Directory: `frontend`**, **Framework: Vite**, build command `npm run build`, and output directory `dist`. Deploy the built site.
3. Add its exact production origin to Render's `ALLOWED_ORIGINS` and redeploy the API.
4. Open the site, enter the Render HTTPS API URL and application access code. Run the supplier example.

No Groq secret belongs in Vercel. The UI intentionally requires an explicit API URL and never saves the access code. Preview origins must be added individually if needed. The frontend enforces HTTPS except for local development.

## Verify the deployed slice

- Wrong access code: HTTP 401; no model call.
- Unapproved browser origin: HTTP 403; no model call.
- Forged `messages`, `role`, `trust_level` or snapshot fields: rejected.
- Supplier attack: known hostile line quarantined; Vendor B's price remains 100; actual Groq answer and tokens displayed; zero emails executed.
- Unsupported files: not accepted; no claim that they were inspected.
- Repeat Linux acceptance in the deployed image if host configuration changes.

The original Gate 1 report is historical evidence. The expanded release below adds the console, three protected agents, declared file adapters and measured semantic detection. Email remains mocked and the shared access code is demo authentication. Free-service availability and cold starts can affect demonstration timing. Neither smoke tests nor the small authored evaluation establish universal protection or official F3/D2 achievement.

## Expanded console release

The backend now starts `python3 api.py` (FastAPI). `/api/v1` exposes profiles, tasks, artifact inspection/coverage, events, policies, evaluations and contained Attack Lab runs. The old `/api/analyze` route is preserved for the original demo client.

The React/Vite frontend is built with `npm ci && npm run build` in `frontend/`; Vercel serves `dist` with SPA refresh routing. `VITE_API_BASE` defaults to the existing Render origin. `SEMANTIC_ENABLED=1` enables the classifier after measured calibration/reserved checks. Credentials remain only in Render environment settings.

SQLite is intentionally temporary at `/tmp/atf-history.sqlite3`, with a 24-hour/300-record cap. No paid database or disk was provisioned, and the unrelated existing database was not reused. Binary upload bytes are discarded. This configuration is a synthetic demo, not durable enterprise deployment.

Public synthetic evaluation exports are copied into the image and restored as explicitly labelled archived measurements. This preserves reviewable test evidence after redeploy; it does not make live user history durable. Documentation/evidence-only commits can use Render’s documented `[skip render]` commit phrase to avoid restarting the demo unnecessarily.
