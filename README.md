# Agent Trust Firewall

A deployed defense-in-depth AI security prototype: a React/TypeScript security console, shared inspection engine and three Groq-powered protected agents. Server policy controls authority, evidence release and external effects even when the model follows an adversarial instruction.

- Console: https://agent-trust-firewall.vercel.app
- API health: https://agent-trust-firewall-api.onrender.com/api/v1/health
- Repository: https://github.com/yalnizcurt/unstopET

The console includes agents/workspaces, file scanning, fragment investigations, real security events, policies, an A/B/C contained Attack Lab, stored evaluation outcomes and deployment settings. Access requires the server-configured demo access code; no Groq key enters the frontend.

Agents: procurement comparison; public HTTPS research through a controlled reader; synthetic repository review with inert patch suggestions. All generation uses the existing verified Linux runtime, trusted Model Gateway and mandatory broker. Mock email requests cannot independently authorize side effects; live email is disabled.

Supported declared adapters: UTF-8 text, static HTML, PDF text/metadata/annotation strings, DOCX XML channels, XLSX cells/hidden sheets/comments, bounded ZIPs. English raster OCR and metadata remain partial; QR decoding and guaranteed recognition are not enabled. Unsupported regions remain withheld. Persistent memory and unrestricted shell/connectors are disabled.

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

The expanded Linux acceptance report records 69 passing checks and two Mac-only skips. Classifier calibration and reserved-variant reports use actual Groq Prompt Guard scores. The authored 42-attack / six-benign detection matrix exercises seven categories across six document surfaces; it is not an unseen-attack reliability estimate. Hosted workflow/evaluation evidence is recorded separately when verified; authored small sets are not universal protection or official F3/D2 achievement.

Free Render history is temporary SQLite, bounded to 24 hours / 300 total records. Raw binaries are discarded after extraction. Synthetic/public demo inputs only; this is not enterprise tenant authentication or durable production audit storage. Free services can sleep and restart.

See [Implementation sequence](IMPLEMENTATION.md), [Architecture](ARCHITECTURE.md), [Security](SECURITY.md), [Agent capabilities](AGENTS.md), [Coverage](COVERAGE.md), [Evaluation](EVALUATION.md) and [Deployment](DEPLOYMENT.md).
