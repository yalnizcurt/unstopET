# Agent Trust Firewall

Runtime security for AI agents: a React/TypeScript security console, shared inspection engine, hosted protected runtime and reusable Python client. Server policy controls authority, evidence release and external effects even when the model follows an adversarial instruction.

- Console: https://agent-trust-firewall.vercel.app
- API documentation: https://agent-trust-firewall-api.onrender.com/api/docs
- API health: https://agent-trust-firewall-api.onrender.com/api/v1/health
- Repository: https://github.com/yalnizcurt/unstopET

The console centers on Protected Agents, Runtime Activity, Security Incidents, read-only Security Policies, Security Lab, Integrations and Settings. Existing file scanning, workspaces, fragment investigation and A/B/C evaluations remain accessible. Access requires the server-configured demo access code; no Groq key enters the frontend.

Agents: procurement comparison; public HTTPS research through a controlled reader; synthetic repository review with inert patch suggestions. All generation uses the existing verified Linux runtime, trusted Model Gateway and mandatory broker. Mock email requests cannot independently authorize side effects; live email is disabled.

Supported declared adapters: UTF-8 text, static HTML, PDF text/metadata/annotation strings, DOCX XML channels, XLSX cells/hidden sheets/comments, bounded ZIPs. English raster OCR and metadata remain partial; QR decoding and guaranteed recognition are not enabled. Unsupported regions remain withheld. Persistent memory and unrestricted shell/connectors are disabled.

Release decision: **READY WITH DISCLOSED LIMITATIONS** for the tested synthetic/public hackathon workflow. All three agents and the hosted walkthrough work. The broader nine-attack set has 8/9 routed detection; general reliability targets, durable multi-user storage and universal protection are not established. See the [release checklist](docs/RELEASE_CHECKLIST.md).

## Local development

The backend requires Linux Landlock ABI 3+ and libseccomp; it deliberately fails closed on unsupported hosts. Use the Docker image on a supported Linux kernel. Set `APP_ACCESS_TOKEN`, `GROQ_API_KEY`, `GROQ_MODEL`, `ALLOWED_ORIGINS` and optionally `SEMANTIC_ENABLED=1` in the trusted server environment. Never place secrets in frontend variables or Git.

```sh
docker build -t agent-trust-firewall .
docker run --rm agent-trust-firewall python3 acceptance.py
# For a Linux development service, provide secrets through your existing secret manager.
cd frontend
npm ci
npm run dev
npm run build
```

The production start command is `python3 api.py`. Versioned APIs live under `/api/v1`; request schemas reject browser-supplied security authority. `VITE_API_BASE` can configure the frontend API URL and is not a credential.

## Verification and limits

The current Linux acceptance report records 108 passing checks and two Mac-only skips; the historical baseline had 82 passing checks. Classifier calibration and reserved-variant reports use actual Groq Prompt Guard scores. The authored 42-attack / six-benign detection matrix exercises seven categories across six document surfaces; it is not an unseen-attack reliability estimate. Final hosted A–G API and browser acceptance is recorded in [submission-readiness-report.json](submission-readiness-report.json); authored small sets are not universal protection or official F3/D2 achievement.

Free Render history is temporary SQLite, bounded to 24 hours / 300 total records. Raw binaries are discarded after extraction. Synthetic/public demo inputs only; this is not enterprise tenant authentication or durable production audit storage. Free services can sleep and restart.

See [Implementation sequence](IMPLEMENTATION.md), [Architecture](ARCHITECTURE.md), [Security](SECURITY.md), [Agent capabilities](AGENTS.md), [Coverage](COVERAGE.md), [Evaluation](EVALUATION.md), [Deployment](DEPLOYMENT.md), [Submission package](SUBMISSION.md), [Release checklist](docs/RELEASE_CHECKLIST.md) and [Implementation audit](docs/IMPLEMENTATION_AUDIT.md).

## Integration-first transformation

The dedicated implementation branch extends the same broker into maximum three model turns / two model-selected tool requests. Tools include released reads, deterministic supplier scoring and inert patch receipts; no direct child network/model/filesystem/shell/MCP path is enabled. Server-issued snapshots and inspection precede every continuation. Failed runs retain chronological evidence.

Use the [Python client](sdk/python/README.md) and [independent reference application](examples/external_procurement_client/README.md) for hosted protected execution. Inspection alone does not enforce your external agent. Source-bound registry verification is distinct from connectivity. See [transformation tracking](docs/PLATFORM_TRANSFORMATION.md), [category crosswalk](docs/OFFICIAL_CATEGORY_CROSSWALK.md) and [platform walkthrough](docs/PLATFORM_DEMO.md). Production verification for the new transformation is reported separately from historical submission evidence.
