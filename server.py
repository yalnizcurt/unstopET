"""Small authenticated Render API. Every agent job uses the verified Linux broker path."""
from collections import deque
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import threading
import time

from firewall import Binding, Denied, Firewall, fields, text
from gate1 import run_runtime, verify_linux_boundary
from groq_ai import GroqProvider

ROOT = Path(__file__).resolve().parent
JOB_LOCK = threading.Lock()
ATTEMPTS = deque()


def analyze(body, provider):
    started = time.monotonic()
    fields(body, ("intent", "evidence"))
    intent = text(body["intent"])
    evidence = body["evidence"]
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 8:
        raise Denied("INVALID_EVIDENCE")
    evidence = [text(item) for item in evidence]
    firewall = Firewall(provider=provider)
    binding = Binding("authenticated-demo-owner", secrets.token_hex(16), secrets.token_hex(16))
    snapshot = firewall.start_task(binding, intent, user_content=evidence)
    result = run_runtime(firewall, binding, "demo", snapshot)
    if result != dict(completed=True) or not firewall.final_outputs:
        raise Denied("AGENT_TASK_FAILED")
    return dict(
        provider="GROQ" if provider else "MOCK", runtime="VERIFIED_LINUX",
        model=getattr(provider, "model", None), usage=getattr(provider, "usage", None),
        seconds=round(time.monotonic() - started, 3),
        output=firewall.final_outputs[-1], policy_version=firewall.policy_version,
        evidence=[dict(source_id=a.id, released_text="\n".join(line for _, line in a.fragments),
                       inspection_profile="gate1-utf8-text-v1", inspection_status=a.inspection_status,
                       may_issue_instructions=False) for a in firewall.artifacts.values()],
        decisions=[dict(operation=e["operation"], result=e["result"], reason=e.get("reason"))
                   for e in firewall.audit], emails_executed=len(firewall.mock_sink),
        supported_formats=["UTF-8 text content"], semantic_detector="NOT_IMPLEMENTED",
    )


def handler(access_token, provider_factory, origins):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # Never log input content, access tokens, or provider credentials.

        def respond(self, status, payload):
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            origin = self.headers.get("Origin")
            if origin in origins:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/api/health":
                self.respond(200, dict(status="READY", isolation="VERIFIED_LINUX", formats=["UTF-8 text"]))
            else:
                self.respond(404, dict(error="NOT_FOUND"))

        def do_OPTIONS(self):
            if self.headers.get("Origin") not in origins:
                self.respond(403, dict(error="ORIGIN_DENIED"))
                return
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Vary", "Origin")
            self.end_headers()

        def do_POST(self):
            self.connection.settimeout(40)
            if self.path != "/api/analyze":
                self.respond(404, dict(error="NOT_FOUND"))
                return
            if not hmac.compare_digest(self.headers.get("Authorization", "").encode(),
                                       ("Bearer " + access_token).encode()):
                self.respond(401, dict(error="AUTHENTICATION_REQUIRED"))
                return
            origin = self.headers.get("Origin")
            if origin and origin not in origins:
                self.respond(403, dict(error="ORIGIN_DENIED"))
                return
            if not JOB_LOCK.acquire(blocking=False):
                self.respond(429, dict(error="BUSY"))
                return
            try:
                now = time.monotonic()
                while ATTEMPTS and ATTEMPTS[0] < now - 60:
                    ATTEMPTS.popleft()
                if len(ATTEMPTS) >= 10:
                    self.respond(429, dict(error="REQUEST_BUDGET_EXHAUSTED"))
                    return
                ATTEMPTS.append(now)
                length = int(self.headers.get("Content-Length", "0"))
                if not 1 <= length <= 65_536 or self.headers.get("Content-Type") != "application/json":
                    raise Denied("INVALID_REQUEST_BODY")
                payload = json.loads(self.rfile.read(length))
                result = analyze(payload, provider_factory())
                self.respond(200, result)
            except Denied as error:
                self.respond(422, dict(error=error.code))
            except (ValueError, TypeError, TimeoutError):
                self.respond(400, dict(error="INVALID_REQUEST"))
            except Exception:
                self.respond(503, dict(error="TASK_UNAVAILABLE"))
            finally:
                JOB_LOCK.release()
    return Handler


if __name__ == "__main__":
    verify_linux_boundary()  # No listening port or credential use before actual containment checks pass.
    access = os.environ.get("APP_ACCESS_TOKEN", "")
    if len(access) < 20:
        raise SystemExit("APP_ACCESS_TOKEN must contain at least 20 characters")
    key = os.environ.get("GROQ_API_KEY")
    test_mode = os.environ.get("ATF_TEST_MODE") == "1"
    if not key and not test_mode:
        raise SystemExit("GROQ_API_KEY is required for live-model deployment")
    origins = set(os.environ.get("ALLOWED_ORIGINS", "http://localhost:3000").split(","))
    factory = (lambda: GroqProvider(key, os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b"))) if key else (lambda: None)
    server = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "10000"))), handler(access, factory, origins))
    print("Linux isolation verified; authenticated API ready.", flush=True)
    server.serve_forever()
