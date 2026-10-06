#!/usr/bin/env python3
"""Serve a generated HTML page through User's Guide DNS/HTTPS hosting.
Every request receives the same file.

    sudo python3 tools/host_standalone.py dist/ps5.html
"""

import argparse
import datetime
import os
import posixpath
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

DEFAULT_TARGET = "manuals.playstation.net"

COLOR = sys.stdout.isatty()


def style(text, *codes):
    return "\033[%sm%s\033[0m" % (";".join(str(c) for c in codes), text) if COLOR else text


def say(text):
    print(text, flush=True)


def good(text):
    say(style("   " + text, 32))


def note(text):
    say(style("   " + text, 36))


def bad(text):
    say(style("   " + text, 31))


# --- the server ------------------------------------------------------------

class SinglePageHandler(BaseHTTPRequestHandler):
    """Answers every request with one file.

    Deliberately not SimpleHTTPRequestHandler: that one maps paths onto a directory
    and 404s what is missing, which is the wrong shape entirely when there is exactly
    one thing to serve. Reading one file into memory once, at startup, also means a
    request cannot be answered differently on a second read -- so what the console
    loaded is exactly what was checked.
    """

    server_version = "PS5StandaloneHost/1.0"
    page = None
    page_name = None

    def log_message(self, fmt, *args):
        pass

    def _log(self, message, error=False):
        if getattr(self.server, "quiet", False):
            return
        say(style("   [HTTP] " + message, 31 if error else 34))

    def do_GET(self):
        self._serve(send_body=True)

    def do_HEAD(self):
        self._serve(send_body=False)

    def _serve(self, send_body):
        agent = self.headers.get("User-Agent", "-")
        requested = self.path.split("?", 1)[0]

        if self.server.target is not None:
            host = self.headers.get("Host", "").split(":", 1)[0].strip().lower()
            if host and host != self.server.target:
                # A Host mismatch means something else on the network asked for this
                # server. Answering it with the page would serve the exploit to a host
                # that did not ask for it.
                self.send_error(403, "Host not allowed")
                self._log("%s %s -> REJECTED (host %s is not %s)"
                          % (self.command, requested, host, self.server.target), error=True)
                return

        body = self.page
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Last-Modified", self.date_time_string(
            datetime.datetime.fromtimestamp(self.server.page_mtime).timestamp()))
        # The exploit is re-run constantly and a stale page costs a reload cycle.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()

        self._log("%s %s -> %s  UA: %s" % (self.command, requested, self.page_name, agent[:48]))
        if "/document/" in requested:
            good("User's Guide document served: %s" % self.page_name)
        # Something the page fetched at runtime. A correctly built page has nothing to
        # fetch, so this line is the first sign of one.
        elif not requested.endswith((".html", "/")):
            note("the page asked for %s -- it should have embedded that instead"
                 % posixpath.basename(requested))

        if send_body:
            self.wfile.write(body)


# --- DNS -------------------------------------------------------------------

def parse_query(data):
    """(transaction id, question bytes, name) or None.

    The question is the QNAME plus QTYPE and QCLASS, echoed verbatim into the answer.
    Only A records are answered: the guide asks for one, and answering anything else
    would be inventing a record format nobody needs.
    """
    if len(data) < 12:
        return None
    qid = data[:2]
    i = 12
    labels = []
    while i < len(data):
        length = data[i]
        if length == 0:
            i += 1
            break
        if length & 0xC0:            # a compression pointer, not a length
            return None
        labels.append(data[i + 1:i + 1 + length])
        i += 1 + length
    if len(data) < i + 4:
        return None
    qtype, _qclass = struct.unpack(">HH", data[i:i + 4])
    if qtype != 1:                   # not A
        return None
    return qid, data[12:i + 4], b".".join(labels).decode("ascii", "replace").lower()


def build_response(qid, question, ip=None):
    """A response echoing `question`, with one A record when `ip` is given.

    NXDOMAIN (rcode 3) when it is not. That is the important half: the console gets no
    address for anything else, which stops it reaching PSN -- which would otherwise
    compete with the User's Guide for the page.
    """
    flags = 0x8180 if ip else 0x8183
    header = qid + struct.pack(">HHHHH", flags, 1, 1 if ip else 0, 0, 0)
    if not ip:
        return header + question
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
    answer += bytes(int(part) for part in ip.split("."))
    return header + question + answer


def build_dns(target, ip, port, verbose):
    class DNSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            parsed = parse_query(data)
            if parsed is None:
                return
            qid, question, name = parsed
            if name == target.lower():
                if verbose:
                    note("DNS: %s -> %s" % (name, ip))
                sock.sendto(build_response(qid, question, ip), self.client_address)
            else:
                if verbose:
                    note("DNS: %s -> NXDOMAIN" % name)
                sock.sendto(build_response(qid, question), self.client_address)

    class DNSServer(socketserver.ThreadingUDPServer):
        allow_reuse_address = True

    # The port is a parameter, not a constant: --dns-port exists so this can be tested
    # without binding the privileged one, and hardcoding 53 here would make --dns-port
    # silently report a port it was not listening on.
    return DNSServer(("0.0.0.0", port), DNSHandler)


def detect_local_ip():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("8.8.8.8", 53))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


# --- entry point -----------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="host_standalone.py",
        description="Serve one generated single-file page to the PS5 User's Guide.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python3 tools/host_standalone.py dist/ps5.html\n"
               "  python3 tools/host_standalone.py dist/ps5.html --http-port 8080\n",
    )
    p.add_argument("page", help="the .html file to serve (from build_standalone.py)")
    p.add_argument("--target", default=DEFAULT_TARGET,
                   help="domain to spoof (default: %s)" % DEFAULT_TARGET)
    p.add_argument("--ip", default=None, help="IP to hand out (default: auto)")
    p.add_argument("--dns-port", type=int, default=53)
    p.add_argument("--https-port", type=int, default=443)
    p.add_argument("--http-port", type=int, default=None,
                   help="also serve plain HTTP, e.g. 8080 to look at it in a desktop browser")
    p.add_argument("--no-dns", action="store_true")
    p.add_argument("--no-https", action="store_true")
    p.add_argument("--cert", default=None, help="PEM certificate (default: generated)")
    p.add_argument("--key", default=None, help="PEM private key")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--no-color", action="store_true")
    return p.parse_args(argv)


def make_cert(target):
    with tempfile.TemporaryDirectory(prefix="ps5-standalone-") as tmp:
        cert = os.path.join(tmp, "cert.pem")
        key = os.path.join(tmp, "key.pem")
        conf = os.path.join(tmp, "openssl.cnf")
        with open(conf, "w") as f:
            f.write(
                "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n"
                "[dn]\nCN = %s\n"
                "[ext]\nsubjectAltName = DNS:%s\nbasicConstraints = critical, CA:FALSE\n"
                % (target, target))
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
             "-sha256", "-keyout", key, "-out", cert, "-config", conf],
            check=True, capture_output=True)
        with open(cert) as f:
            cert_pem = f.read()
        with open(key) as f:
            key_pem = f.read()
    return cert_pem, key_pem


def main(argv=None):
    args = parse_args(argv)
    global COLOR
    if args.no_color:
        COLOR = False

    page_path = os.path.abspath(args.page)
    if not os.path.exists(page_path):
        bad("no such file: %s" % args.page)
        note("build one first: python3 tools/build_standalone.py payloads/<x>.js")
        return 1

    with open(page_path, "rb") as f:
        page = f.read()

    SinglePageHandler.page = page
    SinglePageHandler.page_name = os.path.basename(page_path)

    ip = args.ip or detect_local_ip()

    say("")
    good("PS5 STANDALONE HOST")
    say(style("   serving %s (%.1f KB) -- and nothing else"
               % (SinglePageHandler.page_name, len(page) / 1024.0), 36))
    say(style("   spoofing %s -> %s" % (args.target, ip), 36))
    say("")

    servers = []

    if not args.no_dns:
        try:
            dns = build_dns(args.target, ip, args.dns_port, args.verbose)
            dns.target = args.target
            dns.ip = ip
            dns.verbose = args.verbose
            threading.Thread(target=dns.serve_forever, daemon=True).start()
            good("DNS on UDP %d" % args.dns_port)
            servers.append(dns)
        except OSError as exc:
            bad("could not bind DNS port %d: %s" % (args.dns_port, exc))
            note("ports 53 and 443 are privileged on macOS; try sudo, or --no-dns if the")
            note("console's DNS is already pointed at this PC")
            if args.no_https and args.http_port is None:
                return 1

    if not args.no_https:
        if args.cert and args.key:
            with open(args.cert) as f:
                cert_pem = f.read()
            with open(args.key) as f:
                key_pem = f.read()
        else:
            try:
                cert_pem, key_pem = make_cert(args.target)
            except (OSError, Exception) as exc:  # openssl missing or failing
                bad("could not generate a certificate: %s" % exc)
                note("use --http-port 8080 and look at the page in a desktop browser")
                return 1

        httpd = ThreadingHTTPServer(("0.0.0.0", args.https_port), SinglePageHandler)
        httpd.page_mtime = os.path.getmtime(page_path)
        httpd.target = args.target
        httpd.quiet = not args.verbose

        cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        cert_file.write(cert_pem.encode("ascii"))
        cert_file.close()
        key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        key_file.write(key_pem.encode("ascii"))
        key_file.close()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
        # The console's WebKit may only offer legacy versions and ciphers; macOS ships
        # LibreSSL, which rejects OpenSSL's @SECLEVEL syntax outright, so try the
        # permissive forms in order.
        for spec in ("ALL:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0", "ALL"):
            try:
                ctx.set_ciphers(spec)
                break
            except ssl.SSLError:
                continue
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, ssl.SSLError):
            pass
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        for name in (cert_file.name, key_file.name):
            try:
                os.unlink(name)
            except OSError:
                pass

        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        good("HTTPS on TCP %d (self-signed)" % args.https_port)
        servers.append(httpd)

    if args.http_port is not None:
        httpd = ThreadingHTTPServer(("0.0.0.0", args.http_port), SinglePageHandler)
        httpd.page_mtime = os.path.getmtime(page_path)
        httpd.target = None
        httpd.quiet = not args.verbose
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        good("HTTP on TCP %d (for a desktop browser)" % args.http_port)
        note("open http://localhost:%d/ -- the exploit itself will refuse, since the" % args.http_port)
        note("user agent is not a PS5, but the page and its log will render")
        servers.append(httpd)

    if not servers:
        bad("nothing started")
        return 1

    say("")
    good("Open Settings -> User's Guide on the PS5.")
    if not args.no_dns:
        note("with DNS pointed at %s (Settings -> Network -> Settings -> Set Up" % ip)
        note("Internet Connection -> Set Up Manually -> DNS Settings -> Primary DNS)")
    say("")
    note("Ctrl-C to stop. Set the console's DNS back to automatic afterwards, or it")
    note("has no internet.")
    say("")

    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        say("")
        note("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())