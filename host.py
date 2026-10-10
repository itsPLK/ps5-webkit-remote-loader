#!/usr/bin/env python3
"""PC DNS/HTTPS host for the PS5 User's Guide.

    sudo python3 host.py
    sudo python3 host.py --http-port 8080

Point the console DNS at this PC, then open Settings -> User's Guide.
TLS certificate generation uses openssl unless a certificate is supplied.
"""

import argparse
import base64
import binascii
import datetime
import errno
import io
import mimetypes
import os
import posixpath
import re
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# [[VERSION_PLACEHOLDER]]
VERSION = "0.1.2"
HOST_NAME = "PS5 WEBKIT REMOTE LOADER"

# [[BUILD_TIME_PLACEHOLDER]]
BUILD_TIME = "dev"

# [[SSL_CERT_PLACEHOLDER]]
SSL_CERT_PEM = ""

# [[SSL_KEY_PLACEHOLDER]]
SSL_KEY_PEM = ""

# [[EMBEDDED_ZIP]]
EMBEDDED_ZIP_B64 = ""

_embedded_zip_cache = None
_embedded_zip_loaded = False


def get_embedded_zip():
    """Lazily decode EMBEDDED_ZIP_B64 into an in-memory zipfile.ZipFile."""
    global _embedded_zip_cache, _embedded_zip_loaded
    if not _embedded_zip_loaded:
        _embedded_zip_loaded = True
        if EMBEDDED_ZIP_B64:
            try:
                _embedded_zip_cache = zipfile.ZipFile(
                    io.BytesIO(base64.b64decode(EMBEDDED_ZIP_B64))
                )
            except (binascii.Error, zipfile.BadZipFile):
                _embedded_zip_cache = None
    return _embedded_zip_cache

DEFAULT_TARGET = "manuals.playstation.net"
DEFAULT_TTL = 300
REPO_ROOT = os.path.dirname(os.path.abspath(__file__))


# --- terminal output -------------------------------------------------------

COLOR = sys.stdout.isatty()


def style(text, *codes):
    if not COLOR:
        return text
    return "\033[" + ";".join(str(c) for c in codes) + "m" + text + "\033[0m"


def say(text):
    print(text, flush=True)


def good(text):
    say(style("[+]", 32) + " " + text)


def bad(text):
    say(style("[-]", 31) + " " + text)


def note(text):
    say(style("    " + text, 2))


def bind_hint(service, port, exc):
    """User-facing explanation for a failed bind."""
    if isinstance(exc, PermissionError):
        return (
            f"{service} port {port} is privileged. On Linux and macOS you "
            f"probably need to run this with sudo."
        )
    if getattr(exc, "errno", None) == errno.EADDRINUSE:
        return (
            f"{service} port {port} is already in use. Find the holder with "
            f"`lsof -i :{port}` and stop it, or pass a different port "
            f"(e.g. --dns-port 1053 / --https-port 8443) and set the PS5 DNS "
            f"port to match."
        )
    return ""


# --- local IP --------------------------------------------------------------

def detect_local_ip():
    """Best-effort LAN IP. No traffic is actually transmitted (UDP connect)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def validate_ip(value):
    socket.inet_aton(value)
    return value


# --- DNS -------------------------------------------------------------------

def parse_query(data):
    """Parse the first question of a DNS query.

    Returns (qid, question_bytes, name) with question_bytes being the raw
    question section to echo back, or None if the packet is malformed.
    """
    if len(data) < 12:
        return None
    qid, _flags, qdcount, _, _, _ = struct.unpack(">HHHHHH", data[:12])
    if qdcount < 1:
        return None

    offset = 12
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer: unsupported
            return None
        offset += 1
        if offset + length > len(data):
            return None
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    else:
        return None  # ran off the end without a zero label

    if offset + 4 > len(data):  # need QTYPE + QCLASS
        return None
    end = offset + 4
    return qid, data[12:end], ".".join(labels).lower()


def build_response(qid, question_bytes, ip=None):
    """Build a DNS response. With ip -> one A record; without -> NXDOMAIN."""
    if ip is None:
        flags = 0x8183  # QR + RD + RA + NXDOMAIN
        answer = b""
    else:
        flags = 0x8180  # QR + RD + RA
        answer = (
            b"\xc0\x0c"
            + struct.pack(">HHIH", 1, 1, DEFAULT_TTL, 4)
            + socket.inet_aton(ip)
        )
    header = struct.pack(">HHHHHH", qid, flags, 1, 1 if ip else 0, 0, 0)
    return header + question_bytes + answer


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        parsed = parse_query(data)
        if parsed is None:
            return
        qid, question_bytes, name = parsed
        server = self.server
        server.status.on_dns()
        if name == server.target:
            if server.verbose:
                say(style(f"[DNS]  {name} -> {server.ip}", 36))
            sock.sendto(
                build_response(qid, question_bytes, server.ip), self.client_address
            )
        else:
            if server.verbose:
                say(style(f"[DNS]  {name} -> BLOCKED (NXDOMAIN)", 33))
            sock.sendto(build_response(qid, question_bytes), self.client_address)


class DNSServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, address, target, ip, status, verbose=False):
        self.target = target
        self.ip = ip
        self.status = status
        self.verbose = verbose
        super().__init__(address, DNSHandler)


# --- HTTPS / HTTP ----------------------------------------------------------

class GuideHandler(SimpleHTTPRequestHandler):
    """Serves the repo, rewriting the User's Guide's document path to root."""

    server_version = "PS5WebKitLoaderHost/1.0"

    def __init__(self, *args, allowed_host=None, **kwargs):
        self.allowed_host = allowed_host.lower() if allowed_host else None
        super().__init__(*args, directory=REPO_ROOT, **kwargs)

    def log_message(self, fmt, *args):
        pass  # we do our own logging in send_head()

    def _log(self, message, error=False):
        if getattr(self.server, "quiet", False):
            return
        say(style(f"[HTTP] {message}", 31 if error else 34))

    def log_request(self, code="-", size="-"):
        """Always log the request line, even when not verbose.

        A silent server is the worst thing to debug: if the User's Guide shows
        a cert error or a blank page you need to know whether the request
        arrived at all. This is the line that answers that.
        """
        agent = self.headers.get("User-Agent", "-")
        say(style(f"[HTTP] {self.command} {self.path} -> {code}  UA: {agent[:60]}", 36))

    def _relative_path(self):
        """Request path, normalized and docroot-relative ('' for root).

        Rewrites the User's Guide's own path onto the repo root, so a request
        for /document/en/ps5/index.html returns this repo's index.html.
        """
        path = self.path.split("?", 1)[0].split("#", 1)[0]

        marker = "/document/"
        if path.startswith(marker) and "/ps5/" in path:
            path = "/" + path.split("/ps5/", 1)[1]

        try:
            path = urllib.parse.unquote(path, errors="surrogatepass")
        except UnicodeDecodeError:
            path = urllib.parse.unquote(path)
        path = posixpath.normpath(path)
        words = [
            w
            for w in path.split("/")
            if w and not (os.path.dirname(w) or w in (os.curdir, os.pardir))
        ]
        return "/".join(words)

    def _resolve(self):
        """Return (kind, full_path, shown_name, data, mtime) or None."""
        rel = self._relative_path()
        candidates = [rel]
        if not rel or rel.endswith("/"):
            candidates = [rel + n for n in ("index.html", "index.htm")]

        # Exploit routing based on explicit ?exploit= or User-Agent firmware.
        # Firmware 9.05 and 11.40 do not support Relapse; route them to Poops if present.
        agent = self.headers.get("User-Agent", "")
        m = re.search(r"PlayStation 5/(\d+\.\d+)", agent)
        fw = float(m.group(1)) if m else None
        is_poops_fw = fw is not None and round(fw, 2) in (9.05, 11.40)

        query_exploit = None
        if "?" in self.path:
            qs = urllib.parse.parse_qs(self.path.split("?", 1)[1])
            query_exploit = qs.get("exploit", [None])[0]

        self._routed_fw = fw
        self._routed_poops = is_poops_fw
        self._query_exploit = query_exploit

        want_poops = query_exploit == "poops" or (query_exploit is None and is_poops_fw)
        want_relapse = query_exploit == "relapse"

        if "index.html" in candidates or "index.htm" in candidates:
            if want_poops:
                candidates.insert(0, "poops.html")
            elif want_relapse:
                candidates.insert(0, "relapse.html")

        if "relapse.html" in candidates and "index.html" not in candidates:
            candidates.append("index.html")

        # 1. Embedded zip archive (standalone bundled release mode)
        z = get_embedded_zip()
        if z is not None:
            for candidate in candidates:
                clean = candidate.lstrip("/")
                if clean in z.namelist():
                    info = z.getinfo(clean)
                    data = z.read(info)
                    mtime = datetime.datetime(*info.date_time[:6]).timestamp()
                    return "zip", None, candidate, data, mtime
            return None

        # 2. Local filesystem (development mode from source checkout)
        for candidate in candidates:
            full = os.path.join(REPO_ROOT, candidate)
            try:
                if os.path.commonpath([os.path.abspath(full), REPO_ROOT]) == REPO_ROOT:
                    if os.path.isfile(full):
                        return "file", full, candidate, None, os.path.getmtime(full)
            except (ValueError, OSError):
                pass

        return None

    def _host_allowed(self):
        if self.allowed_host is None:
            return True
        host = self.headers.get("Host", "").split(":", 1)[0].strip().lower()
        return host == self.allowed_host

    def send_head(self):
        raw_path = self.path.split("?", 1)[0].split("#", 1)[0]
        self.server.status.on_http()
        if not self._host_allowed():
            self.send_error(403, "Host not allowed")
            self._log(f"{self.command} {raw_path} -> REJECTED (host mismatch)", error=True)
            return None

        resolved = self._resolve()
        if resolved is None:
            self.send_error(404, "File not found")
            self._log(f"{self.command} {raw_path} -> 404 (not in repo)", error=True)
            return None

        kind, full, shown, data, mtime = resolved
        if kind == "file":
            try:
                with open(full, "rb") as f:
                    data = f.read()
            except OSError as exc:
                self.send_error(500, str(exc))
                self._log(f"{self.command} {raw_path} -> 500 ({exc})", error=True)
                return None

        if data and (b"[[VERSION_PLACEHOLDER]]" in data or b"[[BUILD_TIME_PLACEHOLDER]]" in data):
            data = data.replace(b"[[VERSION_PLACEHOLDER]]", VERSION.encode("utf-8"))
            data = data.replace(b"[[BUILD_TIME_PLACEHOLDER]]", BUILD_TIME.encode("utf-8"))

        ctype = mimetypes.guess_type(shown)[0] or "application/octet-stream"
        if shown.endswith((".js", ".mjs")):
            ctype = "application/javascript"
        elif shown.endswith((".html", ".htm")):
            ctype = "text/html; charset=utf-8"

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Last-Modified", self.date_time_string(mtime))
        # The exploit is re-run constantly and stale JS/offsets files waste a
        # reload cycle, so never let the PS5 cache anything.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.end_headers()
        shown_detail = shown
        if shown == "poops.html" and getattr(self, "_routed_poops", False):
            shown_detail = f"{shown} (PS5 FW {self._routed_fw:.2f} routed to Poops)"
        elif getattr(self, "_query_exploit", None):
            shown_detail = f"{shown} (exploit={self._query_exploit})"
        self._log(f"{self.command} {raw_path} -> {shown_detail}")
        if raw_path.startswith("/document/"):
            self.server.status.on_document()
        return io.BytesIO(data)


def build_server(host, port, allowed_host, status, quiet):
    handler = lambda *a, **kw: GuideHandler(*a, allowed_host=allowed_host, **kw)
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    httpd.status = status
    httpd.quiet = quiet
    return httpd


# --- TLS -------------------------------------------------------------------

def make_cert(target):
    """Self-signed cert for the spoofed hostname, via openssl.

    Includes a subjectAltName because CN-only certificates are rejected by
    current TLS stacks, and drops the floor to TLS 1.0 with legacy ciphers so
    an older WebKit can still complete a handshake.

    Returns (cert_pem, key_pem) or (None, None). A fresh pair is generated per
    run rather than committed, so there is no key to leak and no expiry to
    manage. Pass --cert/--key to pin your own pair instead.
    """
    with tempfile.TemporaryDirectory(prefix="ps5-wkl-") as tmp:
        cert_path = os.path.join(tmp, "cert.pem")
        key_path = os.path.join(tmp, "key.pem")
        conf = os.path.join(tmp, "openssl.cnf")
        with open(conf, "w") as f:
            f.write(
                "[req]\n"
                "distinguished_name = dn\n"
                "x509_extensions = ext\n"
                "prompt = no\n"
                "[dn]\n"
                f"CN = {target}\n"
                "[ext]\n"
                "subjectAltName = DNS:" + target + ", IP:127.0.0.1\n"
                "basicConstraints = critical, CA:FALSE\n"
            )
        try:
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-nodes", "-days", "825", "-sha256",
                    "-keyout", key_path, "-out", cert_path,
                    "-config", conf,
                ],
                check=True,
                capture_output=True,
            )
        except (OSError, subprocess.CalledProcessError):
            return None, None
        with open(cert_path) as f:
            cert = f.read()
        with open(key_path) as f:
            key = f.read()
    return cert, key


class LoggingSSLContext(ssl.SSLContext):
    """TLS context that reports each handshake.

    ssl.SSLContext cannot be subclassed with extra __init__ arguments on every
    Python build, so this takes the protocol the way the stdlib does and only
    adds the logging hook.

    This is the most useful line when the PS5 is not cooperating: it separates
    "the PS5 never reached us" (no line at all) from "the PS5 connected and the
    handshake failed" (handshake FAILED) from "TLS completed and the problem is
    elsewhere" (handshake ok).
    """

    def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True,
                    suppress_ragged_eofs=True, server_hostname=None,
                    session=None):
        try:
            wrapped = super().wrap_socket(
                sock, server_side, do_handshake_on_connect, suppress_ragged_eofs,
                server_hostname, session,
            )
        except ssl.SSLError as exc:
            peer = sock.getpeername() if hasattr(sock, "getpeername") else "?"
            say(style(f"[TLS ] handshake FAILED from {peer[0] if peer != '?' else '?'}"
                      f" -> {exc}", 31))
            raise
        try:
            peer = wrapped.getpeername()
            say(style(f"[TLS ] handshake ok from {peer[0]}: "
                      f"{wrapped.version()} {wrapped.cipher()[0]}", 32))
        except OSError:
            pass
        return wrapped


# --- one-shot status messages ---------------------------------------------

class Status:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.dns = False
        self.http = False
        self.document = False
        self._lock = threading.Lock()

    def _once(self, attr):
        with self._lock:
            if getattr(self, attr):
                return False
            setattr(self, attr, True)
        return True

    def on_dns(self):
        if self._once("dns") and self.enabled:
            say("")
            good("PS5 is talking to us (DNS).")
            note("On the PS5: Settings -> User's Guide")
            note("If the DNS is not set yet, do that first:")
            note("Settings -> Network -> Settings -> Set Up Internet")
            note("Connection -> Set Up Manually -> DNS Settings")
            say("")

    def on_http(self):
        if self._once("http") and self.enabled:
            good("HTTPS request received.")

    def on_document(self):
        if self._once("document") and self.enabled:
            say("")
            good("User's Guide document served.")
            note("The WebKit exploit should be running on the PS5 now.")
            note("It needs several attempts - reload the User's Guide if the")
            note("browser stalls.")
            note("")
            note("When you are done, set the PS5 DNS back to automatic,")
            note("otherwise it has no internet.")
            say("")


# --- main ------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="host.py",
        description="DNS spoofer + HTTPS server so the PS5 User's Guide "
                    "can open this repo over the LAN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  python3 host.py\n"
               "  python3 host.py --http-port 8080   # desktop testing too\n"
               "  python3 host.py --verbose\n",
    )
    p.add_argument("--ip", type=validate_ip, default=None,
                   help="IP to hand out for the spoofed domain (default: auto).")
    p.add_argument("--target", default=DEFAULT_TARGET,
                   help=f"Domain to spoof (default: {DEFAULT_TARGET}).")
    p.add_argument("--dns-port", type=int, default=53,
                   help="DNS UDP port (default: 53).")
    p.add_argument("--https-port", type=int, default=443,
                   help="HTTPS TCP port (default: 443).")
    p.add_argument("--http-port", type=int, default=None,
                   help="Also serve plain HTTP on this port, e.g. 8080 for "
                        "testing in a desktop browser.")
    p.add_argument("--strict-host", action="store_true",
                   help="Only answer requests whose Host header is --target.")
    p.add_argument("--no-dns", action="store_true", help="Disable the DNS server.")
    p.add_argument("--no-https", action="store_true", help="Disable HTTPS.")
    p.add_argument("--verbose", action="store_true",
                   help="Log every DNS, TLS and HTTP event.")
    p.add_argument("--cert", default=None,
                   help="Pinned certificate PEM (default: generate a fresh "
                        "self-signed one for --target).")
    p.add_argument("--key", default=None,
                   help="Pinned private key PEM, used with --cert.")
    p.add_argument("--extract", nargs="?", const="remote-loader", default=None,
                   help="Extract embedded bundle (tools/, payloads/, etc.) to a directory and exit.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color.")
    return p.parse_args(argv)


def main(argv=None):
    global COLOR
    args = parse_args(argv)
    if args.no_color:
        COLOR = False
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except AttributeError:
        pass

    if args.extract:
        z = get_embedded_zip()
        if not z:
            bad("No embedded bundle found in this host script (running from source).")
            return 1
        out_dir = os.path.abspath(args.extract)
        z.extractall(out_dir)
        good(f"Extracted {len(z.namelist())} files to {out_dir}")
        return 0

    if args.no_dns and args.no_https and args.http_port is None:
        bad("every server is disabled, nothing to do.")
        return 1

    ip = args.ip or detect_local_ip()

    width = 52
    def row(t):
        return "   │" + t.center(width) + "│"
    say("")
    say(style("   ┌" + "─" * width + "┐", 36))
    for line in (row(f"{HOST_NAME} v{VERSION}"),
                 row("PS5 User's Guide host"),
                 row("serving " + (os.path.basename(REPO_ROOT) if not EMBEDDED_ZIP_B64 else "embedded bundle"))):
        say(style(line, 36))
    say(style("   └" + "─" * width + "┘", 36))
    say("")

    good(f"Spoofing {style(args.target, 1)} -> {style(ip, 1, 33)}")
    note("everything else gets NXDOMAIN (blocks PSN and update prompts)")
    good(f"Serving {REPO_ROOT if not EMBEDDED_ZIP_B64 else 'embedded in-memory bundle'}")
    if args.verbose:
        good("Verbose mode: per-request logging on.")

    status = Status()
    servers = []

    if not args.no_dns:
        try:
            dns = DNSServer(("0.0.0.0", args.dns_port), args.target, ip,
                            status, args.verbose)
        except OSError as exc:
            bad(f"Could not bind DNS port {args.dns_port}: {exc}")
            hint = bind_hint("DNS", args.dns_port, exc)
            if hint:
                note(hint)
            return 1
        threading.Thread(target=dns.serve_forever, daemon=True).start()
        good(f"DNS on UDP {args.dns_port}")
        servers.append(dns)

    if not args.no_https:
        try:
            httpsd = build_server("0.0.0.0", args.https_port,
                                  args.target if args.strict_host else None,
                                  status, not args.verbose)
        except OSError as exc:
            bad(f"Could not bind HTTPS port {args.https_port}: {exc}")
            hint = bind_hint("HTTPS", args.https_port, exc)
            if hint:
                note(hint)
            return 1

        if args.cert and args.key:
            try:
                with open(args.cert) as f:
                    cert_pem = f.read()
                with open(args.key) as f:
                    key_pem = f.read()
            except OSError as exc:
                bad(f"Could not read --cert/--key: {exc}")
                return 1
            good(f"Using pinned certificate {args.cert}")
        elif SSL_CERT_PEM and SSL_KEY_PEM:
            cert_pem = SSL_CERT_PEM
            key_pem = SSL_KEY_PEM
            if args.verbose:
                good("Using pre-built embedded TLS certificate")
        else:
            cert_pem, key_pem = make_cert(args.target)
            if cert_pem is None:
                bad("Could not generate an HTTPS certificate (openssl missing?).")
                note("Install openssl, or use --http-port 8080 and test in a")
                note("desktop browser instead.")
                return 1

        cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        cert_file.write(cert_pem.encode("ascii"))
        cert_file.close()
        key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        key_file.write(key_pem.encode("ascii"))
        key_file.close()

        ctx = LoggingSSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)
        # An older WebKit may offer only legacy versions/ciphers. macOS ships
        # LibreSSL, which rejects OpenSSL's "@SECLEVEL" syntax outright, so try
        # the permissive forms in order and keep the default if none apply.
        for spec in ("ALL:@SECLEVEL=0", "DEFAULT:@SECLEVEL=0", "ALL"):
            try:
                ctx.set_ciphers(spec)
                break
            except ssl.SSLError:
                continue
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, ssl.SSLError):
            pass  # LibreSSL here will not go below its own floor
        httpsd.socket = ctx.wrap_socket(httpsd.socket, server_side=True)
        # The cert is already loaded into the context, so leaking the temp file
        # is harmless if the OS still holds it open.
        for name in (cert_file.name, key_file.name):
            try:
                os.unlink(name)
            except OSError:
                pass

        threading.Thread(target=httpsd.serve_forever, daemon=True).start()
        good(f"HTTPS on TCP {args.https_port} (self-signed)")
        servers.append(httpsd)

    if args.http_port is not None:
        try:
            httpd = build_server("0.0.0.0", args.http_port, None, status,
                                 not args.verbose)
        except OSError as exc:
            bad(f"Could not bind HTTP port {args.http_port}: {exc}")
            hint = bind_hint("HTTP", args.http_port, exc)
            if hint:
                note(hint)
        else:
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            good(f"HTTP on TCP {args.http_port} (plain, for desktop testing)")
            note(f"open http://localhost:{args.http_port}/ in a desktop browser")
            servers.append(httpd)

    if not servers:
        bad("no server started.")
        return 1

    say("")
    good(f"Set the PS5 DNS to {style(ip, 1, 33)}")
    note("Settings -> Network -> Settings -> Set Up Internet Connection")
    note("-> Set Up Manually -> DNS Settings -> Primary DNS")
    say("")
    good("Waiting for the PS5. Open Settings -> User's Guide when ready.")
    say("")

    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        say("")
        bad("Shutting down.")
        for s in servers:
            try:
                s.shutdown()
                s.server_close()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
