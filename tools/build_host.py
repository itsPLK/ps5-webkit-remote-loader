#!/usr/bin/env python3
"""Build the standalone webkit-remote-loader-host.py PC host script.

Zips the remote loader frontend (index.html, offsets/, shared/, src/, tools/, payloads/),
base64-encodes the archive and injects it along with a pre-generated self-signed TLS certificate
into host.py, so the resulting single-file script can run completely standalone without any external files.

Usage:
    build_host.py [--output FILE]
    build_host.py --page dist/ps5.html --name "PS5 STANDALONE"
"""

import argparse
import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile

from gen_version import get_version_info

CHUNK = 76
MARKER = "# [[EMBEDDED_ZIP]]"
PLACEHOLDER = MARKER + '\nEMBEDDED_ZIP_B64 = ""'
VERSION_MARKER = "# [[VERSION_PLACEHOLDER]]"
VERSION_PLACEHOLDER = VERSION_MARKER + '\nVERSION = "0.1.0"'
BUILD_TIME_MARKER = "# [[BUILD_TIME_PLACEHOLDER]]"
BUILD_TIME_PLACEHOLDER = BUILD_TIME_MARKER + '\nBUILD_TIME = "dev"'
CERT_MARKER = "# [[SSL_CERT_PLACEHOLDER]]"
CERT_PLACEHOLDER = CERT_MARKER + '\nSSL_CERT_PEM = ""'
KEY_MARKER = "# [[SSL_KEY_PLACEHOLDER]]"
KEY_PLACEHOLDER = KEY_MARKER + '\nSSL_KEY_PEM = ""'

CERT_TARGET = "manuals.playstation.net"


def repo_root():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def should_include(rel_path):
    if rel_path.startswith(".git") or "/.git" in rel_path:
        return False
    if rel_path.endswith(".DS_Store"):
        return False
    if rel_path.startswith("third_party"):
        return False
    if rel_path.startswith("installer"):
        return False
    if rel_path.endswith((".elf", ".exe")):
        return False
    if rel_path in ("build_release.sh", "Makefile"):
        return False
    return True


def build_zip(page=None, version="0.1.0", build_time="dev"):
    root = repo_root()
    archive = io.BytesIO()
    file_map = {}

    v_bytes = version.encode("utf-8")
    bt_bytes = build_time.encode("utf-8")

    if page is not None:
        entries = [page] if isinstance(page, str) else list(page)
        for idx, entry in enumerate(entries):
            if "=" in entry:
                arcname, p = entry.split("=", 1)
            else:
                arcname = "index.html" if idx == 0 else os.path.basename(entry)
                p = entry
            file_map[arcname] = p
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            for arcname, p in sorted(file_map.items()):
                with open(p, "rb") as f:
                    data = f.read()
                if b"[[VERSION_PLACEHOLDER]]" in data or b"[[BUILD_TIME_PLACEHOLDER]]" in data:
                    data = data.replace(b"[[VERSION_PLACEHOLDER]]", v_bytes)
                    data = data.replace(b"[[BUILD_TIME_PLACEHOLDER]]", bt_bytes)
                    zf.writestr(arcname, data)
                else:
                    zf.write(p, arcname=arcname)
        return archive.getvalue(), file_map

    # Target items to bundle
    include_paths = [
        "index.html",
        "offsets",
        "shared",
        "src",
        "tools/send.py",
        "payloads",
    ]

    for item in include_paths:
        full_item = os.path.join(root, item)
        if not os.path.exists(full_item):
            continue
        if os.path.isfile(full_item):
            rel = os.path.relpath(full_item, root).replace(os.sep, "/")
            file_map[rel] = full_item
        else:
            for dirpath, dirs, filenames in os.walk(full_item):
                dirs.sort()
                for fname in sorted(filenames):
                    full = os.path.join(dirpath, fname)
                    rel = os.path.relpath(full, root).replace(os.sep, "/")
                    if should_include(rel):
                        file_map[rel] = full

    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for rel in sorted(file_map.keys()):
            p = file_map[rel]
            with open(p, "rb") as f:
                data = f.read()
            if b"[[VERSION_PLACEHOLDER]]" in data or b"[[BUILD_TIME_PLACEHOLDER]]" in data:
                data = data.replace(b"[[VERSION_PLACEHOLDER]]", v_bytes)
                data = data.replace(b"[[BUILD_TIME_PLACEHOLDER]]", bt_bytes)
                zf.writestr(rel, data)
            else:
                zf.write(p, arcname=rel)

    return archive.getvalue(), file_map


def generate_server_cert():
    with tempfile.TemporaryDirectory(prefix="ps5-wkrl-") as tmpdir:
        cert_path = os.path.join(tmpdir, "cert.pem")
        key_path = os.path.join(tmpdir, "key.pem")
        conf = os.path.join(tmpdir, "openssl.cnf")
        with open(conf, "w") as f:
            f.write(
                "[req]\n"
                "distinguished_name = dn\n"
                "x509_extensions = ext\n"
                "prompt = no\n"
                "[dn]\n"
                f"CN = {CERT_TARGET}\n"
                "[ext]\n"
                f"subjectAltName = DNS:{CERT_TARGET}, IP:127.0.0.1\n"
                "basicConstraints = critical, CA:FALSE\n"
            )
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-nodes", "-days", "3650", "-sha256",
                "-keyout", key_path, "-out", cert_path,
                "-config", conf,
            ],
            check=True,
            capture_output=True,
        )
        with open(cert_path) as f:
            cert = f.read()
        with open(key_path) as f:
            key = f.read()
    return cert, key


def embed_payload(source, payload_b64):
    if PLACEHOLDER not in source:
        sys.exit(f"Error: '{PLACEHOLDER}' placeholder not found in host.py")
    chunks = "\n".join(
        '    "%s"' % payload_b64[i : i + CHUNK]
        for i in range(0, len(payload_b64), CHUNK)
    )
    replacement = MARKER + "\nEMBEDDED_ZIP_B64 = (\n" + chunks + "\n)"
    return source.replace(PLACEHOLDER, replacement)


def embed_version(source, version, build_time):
    if VERSION_PLACEHOLDER not in source:
        sys.exit(f"Error: '{VERSION_PLACEHOLDER}' not found in host.py")
    if BUILD_TIME_PLACEHOLDER not in source:
        sys.exit(f"Error: '{BUILD_TIME_PLACEHOLDER}' not found in host.py")
    source = source.replace(VERSION_PLACEHOLDER, VERSION_MARKER + f'\nVERSION = "{version}"')
    return source.replace(BUILD_TIME_PLACEHOLDER, BUILD_TIME_MARKER + f'\nBUILD_TIME = "{build_time}"')


def embed_server_cert(source, cert_pem, key_pem):
    if CERT_PLACEHOLDER not in source:
        sys.exit(f"Error: '{CERT_PLACEHOLDER}' not found in host.py")
    if KEY_PLACEHOLDER not in source:
        sys.exit(f"Error: '{KEY_PLACEHOLDER}' not found in host.py")
    source = source.replace(CERT_PLACEHOLDER, CERT_MARKER + '\nSSL_CERT_PEM = """' + cert_pem + '"""')
    return source.replace(KEY_PLACEHOLDER, KEY_MARKER + '\nSSL_KEY_PEM = """' + key_pem + '"""')


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="build_host.py",
        description="Build standalone webkit-remote-loader-host.py with embedded files and certs.",
    )
    parser.add_argument("--input", default=os.path.join(repo_root(), "host.py"),
                        help="Source host script (default: host.py).")
    parser.add_argument("--output", default=os.path.join(repo_root(), "webkit-remote-loader-host.py"),
                        help="Output script (default: webkit-remote-loader-host.py).")
    parser.add_argument("--version", default=None,
                        help="Explicit full version string to embed (default: computed via gen_version.py).")
    parser.add_argument("--build-time", default=None,
                        help="Explicit build time string to embed (default: computed via gen_version.py).")
    parser.add_argument("--page", action="append", default=[],
                        help="Embed standalone HTML file(s) instead of the repository frontend. "
                             "Can be specified multiple times or as [NAME=]PATH.")
    parser.add_argument("--name", default="PS5 WEBKIT REMOTE LOADER",
                        help="Host banner title.")
    args = parser.parse_args(argv)

    input_path = os.path.abspath(args.input)
    output_path = os.path.abspath(args.output)

    if output_path == input_path:
        sys.exit("Error: --output must differ from --input.")

    version_info = get_version_info()
    version = args.version or version_info["full"]
    build_time = args.build_time or version_info["build_time"]

    pages = args.page if args.page else None
    zip_data, file_map = build_zip(pages, version=version, build_time=build_time)
    raw_size = sum(os.path.getsize(p) for p in file_map.values())
    payload_b64 = base64.b64encode(zip_data).decode("ascii")

    with open(input_path, "r", encoding="utf-8") as f:
        source = f.read()

    built = embed_payload(source, payload_b64)
    built = built.replace('HOST_NAME = "PS5 WEBKIT REMOTE LOADER"',
                          'HOST_NAME = ' + json.dumps(args.name))
    built = embed_version(built, version, build_time)
    cert_pem, key_pem = generate_server_cert()
    built = embed_server_cert(built, cert_pem, key_pem)

    # Sanity-check python compilation
    compile(built, output_path, "exec")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(built)

    print(f"Embedded {len(file_map)} files into {output_path}")
    print(f"  raw files:  {raw_size} bytes -> zip: {len(zip_data)} bytes -> base64: {len(payload_b64)} bytes")
    print(f"  version:    v{version} (built {build_time})")
    print(f"Wrote {output_path} ({len(built)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
