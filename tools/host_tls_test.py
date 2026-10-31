#!/usr/bin/env python3
"""Local socket regression tests for the host's TLS handshake handling."""
import importlib.util
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "guide_host", Path(__file__).resolve().parents[1] / "host.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = str(self.connection.gettimeout()).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class HostTLSTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cert, key = host.make_cert("localhost")
        if cert is None:
            raise RuntimeError("openssl is required for TLS regression tests")
        cert_path = Path(cls.directory.name) / "cert.pem"
        key_path = Path(cls.directory.name) / "key.pem"
        cert_path.write_text(cert)
        key_path.write_text(key)
        cls.context = host.LoggingSSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(cert_path, key_path)

    def start_server(self, tls=True):
        server = host.GuideHTTPServer(("127.0.0.1", 0), Handler)
        server.handshake_timeout = 0.25
        if tls:
            server.ssl_context = self.context
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(2)
        self.addCleanup(cleanup)
        return server, thread

    def request(self, server, tls=True):
        with socket.create_connection(server.server_address, timeout=2) as raw:
            connection = (ssl._create_unverified_context().wrap_socket(
                raw, server_hostname="localhost") if tls else raw)
            with connection:
                connection.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                response = b""
                while True:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        self.assertIn(b"200 OK", response)
        # The handshake deadline must not apply to subsequent HTTP reads.
        self.assertTrue(response.endswith(b"None"), response)

    def test_idle_handshake_does_not_block_https_and_expires(self):
        server, _ = self.start_server()
        with patch.object(host, "say") as log:
            with socket.create_connection(server.server_address, timeout=2) as idle:
                self.request(server)
                self.assertEqual(idle.recv(1), b"")
            self.assertTrue(any("handshake FAILED from 127.0.0.1" in str(call)
                                for call in log.call_args_list))

    def test_shutdown_completes_with_idle_handshake(self):
        server, thread = self.start_server()
        with socket.create_connection(server.server_address, timeout=2):
            stopped = threading.Event()
            def shutdown():
                server.shutdown()
                stopped.set()
            threading.Thread(target=shutdown, daemon=True).start()
            self.assertTrue(stopped.wait(1), "shutdown blocked on TLS handshake")
            thread.join(1)
            self.assertFalse(thread.is_alive())

    def test_bad_handshake_does_not_prevent_next_request(self):
        server, _ = self.start_server()
        with patch.object(host, "say"):
            with socket.create_connection(server.server_address, timeout=2) as bad:
                bad.sendall(b"this is not TLS\r\n")
                try:
                    self.assertEqual(bad.recv(1), b"")
                except ConnectionResetError:
                    pass
            self.request(server)

    def test_plain_http(self):
        server, _ = self.start_server(tls=False)
        self.request(server, tls=False)

    def test_unknown_ca_is_only_logged_in_verbose_mode(self):
        server, _ = self.start_server()
        finished = threading.Event()
        original_shutdown = server.shutdown_request

        def shutdown(request):
            original_shutdown(request)
            finished.set()

        server.shutdown_request = shutdown
        self.addCleanup(setattr, self.context, "verbose", False)
        for verbose in (False, True):
            with self.subTest(verbose=verbose):
                self.context.verbose = verbose
                finished.clear()
                with patch.object(host, "say") as log:
                    with socket.create_connection(server.server_address, timeout=2) as raw:
                        with self.assertRaises(ssl.SSLCertVerificationError):
                            ssl.create_default_context().wrap_socket(
                                raw, server_hostname="localhost")
                    self.assertTrue(finished.wait(2))
                    if verbose:
                        self.assertEqual(log.call_count, 1)
                        self.assertIn("TLSV1_ALERT_UNKNOWN_CA", str(log.call_args))
                    else:
                        log.assert_not_called()


if __name__ == "__main__":
    unittest.main()
