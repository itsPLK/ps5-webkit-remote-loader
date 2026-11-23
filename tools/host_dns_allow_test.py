#!/usr/bin/env python3
"""Regression tests for the opt-in DNS allowlist in host.py."""
import importlib.util
from pathlib import Path
import socket
import struct
import threading
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "guide_host", Path(__file__).resolve().parents[1] / "host.py")
host = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host)

TARGET = "manuals.playstation.net"
SPOOF_IP = "192.0.2.10"


def make_query(name, qtype=1, qid=0x4242):
    question = b""
    for label in name.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00" + struct.pack(">HH", qtype, 1)
    packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question
    return qid, packet, question


def start_server(allow):
    server = host.DNSServer(("127.0.0.1", 0), TARGET, SPOOF_IP,
                            host.Status(enabled=False), False, allow)
    thread = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()

    def cleanup():
        server.shutdown()
        server.server_close()
        thread.join(2)
    return server, cleanup


def ask(server, name, qtype=1):
    qid, packet, question = make_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(packet, server.server_address)
        data, _ = sock.recvfrom(4096)
    return data, question


def header(data):
    return struct.unpack(">HHHHHH", data[:12])


class NameMatchTest(unittest.TestCase):
    def test_exact_and_subdomain_are_case_insensitive(self):
        suffixes = ("github.com",)
        for name in ("github.com", "api.github.com", "API.GitHub.COM"):
            self.assertTrue(host.name_matches(name, suffixes), name)

    def test_suffix_boundary_is_respected(self):
        suffixes = ("github.com",)
        for name in ("notgithub.com", "github.com.evil.example", "github.co"):
            self.assertFalse(host.name_matches(name, suffixes), name)

    def test_empty_allowlist_matches_nothing(self):
        self.assertFalse(host.name_matches("github.com", []))


class WireFormatTest(unittest.TestCase):
    def test_nodata_echoes_question(self):
        qid, _, question = make_query("api.github.com", qtype=28)
        response = host.build_nodata(qid, question)
        self.assertEqual(header(response), (qid, 0x8180, 1, 0, 0, 0))
        self.assertEqual(response[12:], question)

    def test_a_record_layout_unchanged(self):
        qid, _, question = make_query(TARGET)
        response = host.build_response(qid, question, SPOOF_IP)
        self.assertEqual(header(response), (qid, 0x8180, 1, 1, 0, 0))
        self.assertEqual(response[12:12 + len(question)], question)
        self.assertTrue(response.endswith(socket.inet_aton(SPOOF_IP)))


class ServerTest(unittest.TestCase):
    def test_default_mode_spoofs_target_and_blocks_allowlisted_name(self):
        server, cleanup = start_server([])
        self.addCleanup(cleanup)

        response, question = ask(server, TARGET)
        self.assertEqual(header(response), (0x4242, 0x8180, 1, 1, 0, 0))
        self.assertEqual(response[12:12 + len(question)], question)
        self.assertTrue(response.endswith(socket.inet_aton(SPOOF_IP)))

        response, _ = ask(server, "github.com")
        _, flags, qdcount, ancount, _, _ = header(response)
        self.assertEqual(flags & 0xF, 3)  # NXDOMAIN
        self.assertEqual((qdcount, ancount), (1, 0))

    def test_allowlisted_a_forwards_host_resolver_ipv4(self):
        expected = socket.getaddrinfo(
            "localhost", 0, family=socket.AF_INET, type=socket.SOCK_STREAM
        )[0][4][0]
        server, cleanup = start_server(["localhost"])
        self.addCleanup(cleanup)

        response, question = ask(server, "localhost")
        self.assertEqual(header(response)[1] & 0xF, 0)  # NOERROR
        self.assertEqual(header(response)[3], 1)
        self.assertEqual(response[12:12 + len(question)], question)
        self.assertTrue(response.endswith(socket.inet_aton(expected)))

    def test_allowlisted_aaaa_is_nodata(self):
        server, cleanup = start_server(["github.com"])
        self.addCleanup(cleanup)

        response, question = ask(server, "github.com", qtype=28)
        self.assertEqual(header(response), (0x4242, 0x8180, 1, 0, 0, 0))
        self.assertEqual(response[12:], question)

    def test_allowlisted_resolve_failure_is_nxdomain(self):
        server, cleanup = start_server(["github.com"])
        self.addCleanup(cleanup)

        with patch("socket.getaddrinfo", side_effect=OSError("no resolver")):
            response, _ = ask(server, "github.com")
        self.assertEqual(header(response)[1] & 0xF, 3)


class ArgumentsTest(unittest.TestCase):
    def test_defaults_keep_allowlist_off(self):
        args = host.parse_args([])
        self.assertEqual(args.allow, "")
        self.assertFalse(args.allow_github)

    def test_allow_flags_parse(self):
        args = host.parse_args(["--allow", "github.com, github.io",
                                "--allow-github"])
        self.assertEqual(args.allow, "github.com, github.io")
        self.assertTrue(args.allow_github)

    def test_github_suffixes_cover_expected_hosts(self):
        for suffix in ("github.com", "github.io", "githubusercontent.com",
                       "githubassets.com", "githubapp.com"):
            self.assertIn(suffix, host.GITHUB_SUFFIXES)


if __name__ == "__main__":
    unittest.main()
