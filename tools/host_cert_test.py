#!/usr/bin/env python3
"""Check runtime and bundled certificate validity with real OpenSSL commands."""
import importlib.util
from pathlib import Path
import ssl
import subprocess
import tempfile
import time
import unittest

import build_host

spec = importlib.util.spec_from_file_location(
    "guide_host", Path(__file__).resolve().parents[1] / "host.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class CertificateTest(unittest.TestCase):
    def check_certificate(self, generate, hostname, days):
        before = time.time()
        cert, key = generate()
        after = time.time()
        self.assertIsNotNone(cert)
        with tempfile.TemporaryDirectory() as directory:
            cert_path = Path(directory) / "cert.pem"
            key_path = Path(directory) / "key.pem"
            cert_path.write_text(cert)
            key_path.write_text(key)
            dates = subprocess.check_output(
                ["openssl", "x509", "-in", str(cert_path), "-noout", "-dates"],
                text=True).splitlines()
            start, end = [ssl.cert_time_to_seconds(line.split("=", 1)[1])
                          for line in dates]
            self.assertGreaterEqual(start, int(before) - 86400)
            self.assertLessEqual(start, after - 86400)
            self.assertGreaterEqual(end, int(before) + days * 86400)
            self.assertLessEqual(end, after + days * 86400)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            details = subprocess.check_output(
                ["openssl", "x509", "-in", str(cert_path), "-noout", "-text"], text=True)
            self.assertIn("DNS:" + hostname, details)
            self.assertIn("IP Address:127.0.0.1", details)
            self.assertIn("CA:FALSE", details)
            for offset in (-300, -23 * 3600, 0, 300, -25 * 3600):
                result = subprocess.run(
                    ["openssl", "verify", "-CAfile", str(cert_path),
                     "-check_ss_sig", "-purpose", "sslserver",
                     "-attime", str(int(after + offset)), str(cert_path)],
                    capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, offset != -25 * 3600,
                                 result.stdout + result.stderr)

    def test_runtime_certificate(self):
        self.check_certificate(lambda: host.make_cert("localhost"), "localhost", 825)

    def test_bundled_certificate(self):
        self.check_certificate(build_host.generate_server_cert,
                               build_host.CERT_TARGET, 3650)


if __name__ == "__main__":
    unittest.main()
