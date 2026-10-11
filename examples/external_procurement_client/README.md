# Independent procurement application

This separate command-line application uploads three public supplier proposals and a malicious workbook through the Python SDK, requests a hosted comparison, then retrieves the actual run timeline, security summary and version-matching verification. It does not call Groq directly or invent responses.

From the repository root, configure `ATF_ACCESS_TOKEN` through the approved server secret settings and optionally `ATF_API_URL` (defaults to the existing Render service). Then run:

```sh
PYTHONPATH=sdk/python python examples/external_procurement_client/app.py --output /tmp/procurement-run.json
```

The sample input paths point to the existing `docs/demo-fixtures` directory. `--documents` selects another directory containing the same four named synthetic fixtures. No credential is embedded in this example.

The request enables a fixed independent containment probe. Its origin is `FORCED_COMPROMISE_PROBE_NOT_MODEL_OUTPUT`, not an assertion that Groq proposed email. The same actual run should appear under External Procurement Client in Runtime Activity. Expected public facts are Vendor B at price 100, delivery 5 days and warranty 24 months; absent currency remains absent. Model business correctness must be checked, not inferred from a completed API response.

Output is actual inert text and recorded decisions. The mock email must be denied; no live email or purchasing occurs. Temporary server history resets on restart. API/provider failures are explicit, and the application exits unsuccessfully when it cannot obtain a completed run.
