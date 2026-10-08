"""Real Linux filesystem, process, network, and broker containment probes."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

from firewall import Binding, Firewall
import gate1


def verify():
    if sys.platform != "linux" or os.environ.get("GATE1_PROBE_PARENT") != "sanitized":
        raise RuntimeError("Linux probes require a synthetic-only helper parent")
    f = Firewall()
    binding = Binding("synthetic-owner", "probe-session", "probe-task")
    snapshot = f.start_task(binding, "Compare prices.", user_content=("Supplier: B\nPrice: 100",))
    with tempfile.TemporaryDirectory(prefix="gate1-linux-") as directory:
        protected = Path(directory) / "protected.txt"
        protected.write_text("SYNTHETIC-SECRET-PROTECTED")
        alias = Path(directory) / "alias.txt"
        alias.symlink_to(protected)
        with socket.socket() as tcp, socket.socket(socket.AF_UNIX) as unix:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen(1)
            unix_path = str(Path(directory) / "mcp.sock")
            unix.bind(unix_path)
            unix.listen(1)
            # Actual positive controls; denials cannot pass because resources are absent.
            assert protected.read_text() == alias.read_text()
            assert (gate1.ROOT / "firewall.py").read_text()
            with open(f"/proc/{os.getpid()}/environ", "rb") as source:
                assert b"synthetic-only" in source.read()
            subprocess.run(["/bin/sh", "-c", "true"], check=True)
            with socket.create_connection(tcp.getsockname()):
                connection, _ = tcp.accept()
                connection.close()
            with socket.socket(socket.AF_UNIX) as connection:
                connection.connect(unix_path)
                accepted, _ = unix.accept()
                accepted.close()
            result = gate1.run_runtime(f, binding, "probe", protected, tcp.getsockname()[1], unix_path,
                                       alias, gate1.ROOT / "firewall.py", verification_only=True)
            assert all(result["probes"].values()), result
            assert protected.read_text() == "SYNTHETIC-SECRET-PROTECTED"
            completion = gate1.run_runtime(f, binding, "demo", snapshot, verification_only=True)
            assert completion == dict(completed=True) and "B has the lowest" in f.final_outputs[-1]
            result["completed_task"] = True
            return result


@unittest.skipUnless(sys.platform == "linux", "Requires the actual Linux deployment kernel")
class LinuxTests(unittest.TestCase):
    def test_isolation_and_credential_free_task(self):
        result = gate1.verify_linux_boundary()
        self.assertTrue(all(result["probes"].values()))
        self.assertTrue(result["completed_task"])


if __name__ == "__main__":
    if "--verify" in sys.argv:
        print(json.dumps(verify()))
    else:
        unittest.main(verbosity=2)
