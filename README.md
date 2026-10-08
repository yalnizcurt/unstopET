# Agent Trust Firewall

Working **Gate 1 text prototype**: a browser interface, authenticated API, real Groq generation, server-owned context, mandatory execution broker, and an isolated Linux agent. This is the first vertical slice of the [approved five-gate plan](agent-trust-firewall-implementation-plan.md), not the completed multiformat product.

The Linux deployment image passed **44 tests, with 2 macOS-only tests skipped**. Actual file, credential, network, shell and alternate-connector probes were denied, while the authorized comparison task completed. See [Linux acceptance evidence](gate1-linux-acceptance-report.json). Each API startup repeats the real isolation checks before accepting jobs. Render's deployed service passed its startup checks and the hosted browser completed an actual Groq task; see [cloud evidence](cloud-deployment-report.json). Unsupported host kernels cause startup to fail closed.

## Deployment

The deployed interface is at **https://agent-trust-firewall.vercel.app**; its API is **https://agent-trust-firewall-api.onrender.com**. Vercel hosts `frontend/`; Render runs the Docker API. The Groq key is configured only in Render's server environment. Enter the separate `APP_ACCESS_TOKEN` from this service's Render Environment page to run the agent. No access code or provider key is embedded in the static frontend. See [deployment instructions](DEPLOYMENT.md).

The frontend is one static HTML page. The backend uses Python's standard library plus the operating system's `libseccomp2`. No frontend build or package installation is required.

## Local Linux run

```sh
docker build -t agent-trust-firewall .
docker run --rm agent-trust-firewall python3 acceptance.py
docker run --rm -p 127.0.0.1:10000:10000 \
  -e GROQ_API_KEY -e APP_ACCESS_TOKEN \
  -e ALLOWED_ORIGINS=http://localhost:3000 agent-trust-firewall
python3 -m http.server 3000 --bind 127.0.0.1 --directory frontend
```

Set `GROQ_API_KEY` and a separate `APP_ACCESS_TOKEN` of at least 20 characters in the trusted shell before starting the API. Open `http://localhost:3000`, enter `http://localhost:10000` and the application access code. Enter the authorized task separately from untrusted pasted content or UTF-8 `.txt` files. The interface displays the actual model response, released evidence, broker decisions and provider-reported token usage.

For offline API checks, omit the Groq key and explicitly set `ATF_TEST_MODE=1`. Results are labeled **MOCK**. Never use that mode as evidence of real AI performance. `python3 broker_demo.py` is a separate trusted-process mock fixture.

This macOS workspace has a project-local Lima VM with no host mounts for Linux testing. Native macOS execution remains disabled after a synthetic parent-environment probe exposed a bypass. The original [macOS failure report](gate1-acceptance-report.json) is preserved as historical evidence. It is not the current Linux result.

## Security boundary

The child runs with an empty environment and only inherited broker pipes. Linux Landlock (ABI 3+) denies protected files and `/proc` credentials; an irreversible seccomp allowlist denies networking, process creation, execution and filesystem mutations. Resource limits apply. Missing kernel/library support prevents the server from starting. The trusted application, Python standard library, provider transport and operating system remain trusted components.

| Operation | Enforcement |
|---|---|
| `model.generate` | Server-built messages; snapshot ownership, expiry, policy, released hashes, coverage and budgets; provider egress DLP |
| `read_evidence` | Current snapshot and authorized evidence; released text only |
| `email.prepare` | Exact server-granted destination, pinned released attachments, payload and lineage DLP |
| `email.dispatch` | Exact server permit; execution-time authorization/policy/payload revalidation; atomic single use; **mock sink** |
| `finalize` | Current context, bounded output and final DLP |
| `memory.write` | Denied while persistent memory is disabled |
| Shell, HTTP, external MCP, policy changes and unknown operations | Denied; no agent adapters registered |

The web demo grants no email permission. It rejects browser-supplied roles, snapshots and trust labels. A deliberately compromised model's proposed email is blocked independently of detection. API access uses one shared demo access code, exact browser origins, one concurrent job and a ten-attempt-per-minute budget. This is not production tenant authentication or a horizontally scaled service.

## Real AI evidence

[The recorded Groq comparison](groq-live-report.json) contains eight actual model calls: four authored cases, each tested directly and with broker defenses. Direct answers followed the attacker objective in two cases; protected answers completed the task in all four. Those runs were trusted-process smoke tests before Linux isolation was enabled, not a held-out evaluation.

The working interface was subsequently tested against the isolated Linux API with live Groq generation; see [the browser evidence](groq-linux-ui-report.json). The current default model is `openai/gpt-oss-20b`. Groq is the task model; a semantic **security classifier has not yet been evaluated**. Model requests use verified TLS, a fixed endpoint, no redirects or environment proxies, bounded sizes/tokens, a 15-second timeout and no automatic retries. Provider errors omit response bodies and credentials.

`python3 groq_ai.py` performs an opt-in synthetic comparison, using a trusted environment key or hidden terminal input. It never saves the key or executes email.

## Actual coverage

Only UTF-8 **text content** is accepted: up to eight inputs, 16 KiB each, with additional request/model budgets. The versioned inspection profile uses limited deterministic signatures and line quarantine. COMPLETE means the supported text channel was processed; it does not mean all possible attacks were detected. Incomplete or changed evidence is withheld. No complete-file safety claim is made.

HTML, PDF, DOCX, XLSX, images, archives, OCR, audio/video, semantic detection, persistent memory and cross-source correlation are not implemented. Audit/state is in memory; DLP covers configured synthetic/Groq secret signatures and confidential lineage, not arbitrary enterprise secrets. External email delivery is mocked. No universal protection, seven-category coverage, F3 or D2 achievement is claimed.

Gate 2 adds shared inspection contracts and evaluates a purpose-trained semantic classifier. Gate 3 prioritizes measured seven-category detection and supported adapters. Gate 4's correlation/memory remain optional. Gate 5 requires matched baselines and independent attack-family evaluation.
