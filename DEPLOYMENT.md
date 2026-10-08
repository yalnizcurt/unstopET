# Vercel + Render deployment

Repository: https://github.com/yalnizcurt/unstopET

## Render API

1. Sign in to an existing Render account and create a Blueprint from this repository's `main` branch. `render.yaml` selects a free Docker web service.
2. Set `GROQ_API_KEY` as a server environment secret. Do not add it to Git, a frontend field, a Docker build argument or browser storage.
3. Keep the generated `APP_ACCESS_TOKEN`. This shared demo access code authorizes paid model calls; disclose it only to demo users.
4. Set `ALLOWED_ORIGINS` to the exact Vercel production origin, such as `https://your-project.vercel.app`. Multiple exact origins can be comma-separated. Do not use `*`.
5. Deploy and inspect startup logs. Success is `Linux isolation verified; authenticated API ready.` Confirm `/api/health` reports `READY` and `VERIFIED_LINUX`.

Startup launches a synthetic-only compromised child and tests filesystem, parent credentials, networking, shell execution and alternate connectors. It also completes a legitimate brokered task. The container requires Landlock ABI 3+ and usable seccomp; Render's actual host has not been tested yet. If its security policy/kernel disallows these controls, the service stays unavailable. Do not remove restrictions or substitute an unrestricted child to get a successful deploy.

The Docker image runs as a non-root user and binds Render's `PORT`. The application verifies boundaries before reading the provider key or opening the HTTP listener. No storage disk, queue, second microservice or paid service is required for this slice.

## Vercel interface

1. Import this repository into Vercel.
2. Set **Root Directory: `frontend`**, **Framework: Other**, and leave the build command unset. Deploy the static site.
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

This publishes only Gate 1. Email is mocked, semantic detection and other formats remain disabled, and the shared access code is demo authentication. Free-service availability and cold starts can affect demonstration timing. Cloud acceptance must be recorded after successful host startup and an actual browser-to-API-to-Groq run.
