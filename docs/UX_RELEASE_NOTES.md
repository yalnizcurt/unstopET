# Final product experience

The frontend keeps the existing React console, eight primary navigation entries and authenticated API contract. Protected operations still use the server access code. The public walkthrough is now directly accessible at `/#Walkthrough`; opening it does not request protected records or paid inference.

## What changed

- The walkthrough follows Connect → Protect → Execute → Investigate → Validate. It shows the authorized supplier task, hostile hidden-sheet instruction, inspection/context/action boundaries and the three bounded reference integrations.
- Three captured console images are packaged publicly with explicit historical backend `748a60d` captions. They contain approved synthetic demo evidence and are not labelled as current deployment screenshots. Full-size images open separately.
- The archived `8a412ab` / `openai/gpt-oss-120b` A/B/C report supplies the displayed denominators: ten authored cases, nine attacks and one benign case. Detection is B 7/9 and C 8/9; legitimate-task success is A 5/10 and B/C 10/10. A has one observed attacker objective among five scored outcomes and four unknowns. Twenty forced B/C email probes are identified as independent containment tests.
- The new first-use challenge is prominently disclosed beside those familiar-case results: B and C detect 4/48 attacks, flag 6/16 benign cases and gain zero additional semantic detections. This is offline inspection evidence, not agent behavior or execution evidence. Public training overlap is unknown; the separately authored attacks were not blinded.
- Both file inputs clear their native selection before asynchronous work. A user can retry the same file after a busy response. Completed uploads become visible immediately, so a later failure in a batch does not hide already persisted artifacts. Scanner uploads do not silently attach evidence to a task.
- Request errors explain busy, budget, authentication and unavailable-record states. Unknown service responses cannot display arbitrary raw error text.
- Runtime traces label forced probes directly in the collapsed timeline. User-selected retrieval plans are distinguished from agent proposals. Expired/evicted selected runs show that their displayed trace was previously loaded in this browser.
- Runtime verification and parser completeness are explicitly limited to declared controls/channels. Overview counts distinguish output release from scored task utility and identify forced tests within broker denials.
- Mobile layouts wrap headings, long decision text and statistics; wide tables remain horizontally scrollable within their panels.

## Verification

`npm test` passes four suites: routes, nested inventory, pinned deployment/cache behavior, and safe error/report-bound walkthrough values. The archived walkthrough figures are compared to their case-level reports rather than asserted as new live counters. `npm run build` passes TypeScript and Vite.

The installed Chromium browser was exercised locally at **1440×1000** and **390×844**. At both widths the checks covered all eight primary navigation routes, public direct-link/back navigation, zero public protected-API requests, same-file retry in Scanner and Workspace after a busy response, visible forced/source-plan labels, expired-history messaging and horizontal overflow. No page JavaScript errors were observed. The executable test and measured report are in `frontend/tests/browser_ux.py` and `frontend/tests/browser-ux-report.json`.

These browser tests intercept API calls using UI fixtures and already recorded synthetic workflow data. They prove the frontend interactions and responsive layout; they are **not live backend/model acceptance**. Screenshots in `/tmp/atf-frontend-ux` carry that scope. The release lead separately verifies the final hosted runtime and captures current production evidence.

No new paid integration, backend capability, credentials, model access, agent permission or API authentication exception was introduced. Real-device touch/assistive-technology testing and enterprise usability studies remain outside this local browser check.
