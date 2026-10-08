"""Isolated, credential-free agent fixture. All model/operation access is parent-brokered."""
import json
import errno
import ctypes
import os
from pathlib import Path
import socket
import subprocess
import sys

DENIAL_ERRORS = []

if sys.platform == "linux":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from linux_guard import restrict
    restrict()

def request(op, **args):
    print(json.dumps(dict(op=op, args=args)), flush=True)
    return json.loads(sys.stdin.readline())


def denied(operation, allowed_errors=(1, 13)):
    try:
        operation()
    except PermissionError:
        DENIAL_ERRORS.append(1)
        return True
    except OSError as exc:
        DENIAL_ERRORS.append(exc.errno)
        return exc.errno in allowed_errors
    return False


def dns_packet(port):
    # Socket creation alone is not egress. Test an actual datagram to a known local endpoint.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.sendto(b"synthetic-dns-probe", ("127.0.0.1", port))


def unix_connection(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.connect(path)


def parent_environment_query():
    # The test launcher uses a synthetic-only parent. Do not decode or emit any returned bytes.
    if sys.platform == "linux":
        with open(f"/proc/{os.getppid()}/environ", "rb") as source:
            source.read(65_536)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, os.getppid())  # CTL_KERN, KERN_PROCARGS2, parent PID
    length = ctypes.c_size_t()
    if libc.sysctl(mib, 3, None, ctypes.byref(length), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "process environment query denied")
    buffer = ctypes.create_string_buffer(min(length.value, 65_536))
    length = ctypes.c_size_t(len(buffer))
    if libc.sysctl(mib, 3, buffer, ctypes.byref(length), None, 0) != 0:
        raise OSError(ctypes.get_errno(), "process environment read denied")


if sys.argv[1] == "probe":
    protected = Path(sys.argv[2])
    probes = dict(
        protected_read=denied(lambda: protected.read_text()),
        protected_write=denied(lambda: protected.write_text("overwritten")),
        volume_alias_read=denied(lambda: Path(sys.argv[5] if sys.platform == "linux" else "/System/Volumes/Data" + str(protected)).read_text()),
        network=denied(lambda: socket.create_connection(("127.0.0.1", int(sys.argv[3])), timeout=1)),
        dns_egress=denied(lambda: dns_packet(int(sys.argv[3]))),
        # A fork also hits the process resource limit (EAGAIN). Direct exec separately tests the allowlist.
        shell=denied(lambda: subprocess.run(["/bin/sh", "-c", "true"], check=True), (0, 1, 13, errno.EAGAIN)),
        direct_shell_exec=denied(lambda: os.execve("/bin/sh", ["/bin/sh", "-c", "exit 73"], {}), (0, 1, 13)),
        alternate_unix_connector=denied(lambda: unix_connection(sys.argv[4])),
        core_import=denied(lambda: Path(sys.argv[6] if sys.platform == "linux" else Path(__file__).with_name("firewall.py")).read_text()),
        credential_absent="FIREWALL_PROBE_CREDENTIAL" not in os.environ,
        parent_environment=denied(parent_environment_query),
    )
    for operation in ("shell", "http", "external_mcp", "set_policy", "memory.write"):
        response = request(operation)
        probes["broker_" + operation] = not response["ok"]
    print(json.dumps(dict(probes=probes, error_codes=DENIAL_ERRORS)), flush=True)
elif sys.argv[1] == "demo":
    snapshot_id = sys.argv[2]
    if len(sys.argv) > 3 and sys.argv[3] == "collect":
        collected = request("tools.collect", snapshot_id=snapshot_id)
        if not collected["ok"]:
            print(json.dumps(dict(completed=False)), flush=True)
            raise SystemExit(0)
        snapshot_id = collected["result"]["snapshot_id"]
    response = request("model.generate", snapshot_id=snapshot_id)
    if response["ok"]:
        try:
            proposed = json.loads(response["result"]["text"]).get("requested_email")
        except (ValueError, AttributeError):
            proposed = None
        if isinstance(proposed, dict):
            request("email.prepare", snapshot_id=snapshot_id,
                    recipient=proposed.get("recipient"), body=proposed.get("body"))
        output = request("finalize", snapshot_id=snapshot_id, body=response["result"]["text"])
        print(json.dumps(dict(completed=output["ok"])), flush=True)
    else:
        print(json.dumps(dict(completed=False)), flush=True)
else:
    raise SystemExit("Unsupported runtime mode")
