# Agent Trust Firewall submission package

The working prototype combines bounded agent workflows with independent action control. The first-use evaluation exposes a substantial detection gap, so this package supports a **scoped prototype demonstration**, not a claim of general prompt-injection reliability.

- Product: [Agent Trust Firewall](https://agent-trust-firewall.vercel.app)
- Backend: [Hosted API](https://agent-trust-firewall-api.onrender.com)
- Repository: [unstopET](https://github.com/yalnizcurt/unstopET)
- Presentation: [editable PowerPoint](pitch/Agent-Trust-Firewall.pptx) and [submission PDF](pitch/Agent-Trust-Firewall.pdf)
- Architecture: [editable diagram source](ARCHITECTURE.md), seventh slide and [exported PNG](architecture.png)
- Source attribution and metric interpretation: [SOURCES.md](SOURCES.md)
- Demo narration and exact 180-second shot list: [DEMO_VIDEO_SCRIPT.md](../docs/DEMO_VIDEO_SCRIPT.md)
- Evidence records: `evidence/`, plus the source-bound reports linked by the release documentation

## Evidence separation

| Experiment | Denominator and result | What it measures |
|---|---|---|
| First-use static inspection | 48 distinct attacks and 16 benign controls. B/C both detect 4/48 and flag 6/16 benign cases. Public subset: 0/32 detected. | Detection, false positives, fragment preservation and inspection latency. No agent-level prevention claim. |
| Authored hosted A/B/C comparison | Nine attacks and one benign case per configuration. B detects 7/9, C 8/9. Both achieve 10/10 authorized fixture tasks. | Familiar synthetic task behavior and routed AI’s incremental value on that fixture. |
| Familiar format matrix | 28 authored payloads × six formats. 66/84 attack wrappers detected, 0/84 benign wrappers flagged. | Regression across format wrappers, not independent attack breadth. |
| Forced-compromise tests | Source-bound Linux and broker probes, with explicit positive controls and legitimate completion. | Independent containment even when an agent proposes a forbidden action. |
| Actual business workflow smoke tests | Separate Procurement, Research and Developer runs with real model requests and bounded-tool receipts. | Each registered profile’s distinctive useful workflow. |

## Submission prerequisites

The editable deck contains visible placeholders for team name, members and contributions until the human team supplies them. No names are invented.

The actual browser MP4 is being recorded from the final deployed application; exported playback verification is pending. A complete narration script and shot list are ready. Confirm 2–4 minute duration and play the exported MP4 before submitting. If audio capture is unavailable, label a captioned recording accurately and include the narration script.

The deck’s actual production captures identify frontend `cbedb770eb65d2cf2732e6cf4ae4975f8c0a83ce`, backend `aca81e6a06fcb36104d101298eb7162f0a4534ca`, and SDK run `ea056be9628a677dfaddc91af4d7cbb9`. The authored A/B/C results retain historical source `8a412ab`; frozen first-use results remain unchanged. Latest Linux acceptance is 120 passed, zero failures/errors, two Mac-only skips (122 total). The Developer’s generated patch is an inert proposal containing identified correctness issues, not executed or verified code. Authentication for protected operations, runtime isolation and mandatory broker checks must remain intact.
