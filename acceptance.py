"""Emit reproducible Linux acceptance evidence; never requires a live provider key."""
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import platform
import sys
import unittest

from gate1 import verify_linux_boundary

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromNames([
        "test_gate1", "test_groq", "test_linux", "test_server", "test_platform", "test_parsing_linux"])
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    probes = verify_linux_boundary() if result.wasSuccessful() else None
    report = dict(
        scope="Linux agent and parser containment, shared inspection and versioned API integration",
        created_at=datetime.now(timezone.utc).isoformat(),
        status="PASS" if result.wasSuccessful() and probes else "FAIL",
        tests_run=result.testsRun, passed=result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        failures=len(result.failures), errors=len(result.errors),
        skipped=[dict(test=str(test), reason=reason) for test, reason in result.skipped],
        platform=platform.platform(), python_version=platform.python_version(),
        source_sha256={name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in (
            "firewall.py", "gate1.py", "agent_runtime.py", "linux_guard.py", "groq_ai.py", "server.py", "api.py", "inspection.py", "extractors.py", "parser_worker.py", "parsing.py", "network.py")},
        isolation=probes, runtime_enabled=bool(probes), email_executor="MOCK",
        supported_formats=["UTF-8 text", "static HTML", "PDF declared channels", "DOCX XML", "XLSX XML", "bounded ZIP", "raster metadata only"], semantic_detector="PROMPT_GUARD_EVALUATED_SEPARATELY",
        persistent_memory="DISABLED", cloud_runtime_verified=False,
        f3_achieved=False, d2_achieved=False, test_evidence=output.getvalue().splitlines(),
    )
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["status"] == "PASS" else 1)
