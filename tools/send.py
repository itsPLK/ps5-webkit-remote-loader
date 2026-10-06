#!/usr/bin/env python3
"""Send a payload to the PS5 WebKit Remote Loader and stream its logs back.

Zero dependencies beyond the Python 3 standard library.

    python3 tools/send.py <ps5-ip> <port> payload.js
    python3 tools/send.py <ps5-ip> <port> --status
    python3 tools/send.py <ps5-ip> <port> --disconnect
    python3 tools/send.py <ps5-ip> <port> --raw payload.js

Protocol (see src/loader.js):
  -> u64 little-endian size, then `size` bytes of JavaScript source
  -> a size of 0xFFFFFFFF is a command: the next byte is the command id
     (0 disconnect, 1 status, 2 list)
  <- a stream of "[+] log line" text; a binary blob arrives framed as
     13 37 13 37 | u32 length | payload

Logs print live. A payload's output is not line-buffered on the console side,
so use --raw when you want to see bytes exactly as they arrive.
"""

import argparse
import os
import re
import select
import socket
import struct
import sys

CMD_DISCONNECT = 0
CMD_STATUS = 1
CMD_LIST = 2
COMMAND_MAGIC = 0xFFFFFFFF
ARGV_MAGIC = 0xFFFFFFFE
BLOB_MAGIC = b"\x13\x37\x13\x37"

# The loader prefixes every line with one of these.
LINE_RE = re.compile(rb"\[[\-\+\*]\] ")


def color_enabled():
    return sys.stdout.isatty()


def paint(text, code):
    if not color_enabled():
        return text
    return f"\033[{code}m{text}\033[0m"


def emit(chunk, raw):
    """Print a chunk of loader output, colouring the log markers."""
    if raw:
        sys.stdout.write(chunk.decode("latin-1"))
        sys.stdout.flush()
        return

    text = chunk.decode("latin-1", "replace")
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\n")
        if not body:
            continue
        if body.startswith("[+]"):
            body = paint(body, 32)
        elif body.startswith("[-]"):
            body = paint(body, 31)
        elif body.startswith("[*]"):
            body = paint(body, 36)
        sys.stdout.write(body + "\n")
    sys.stdout.flush()


def frame_blobs(buffer, on_blob, raw=False):
    """Split framed binary blobs out of the stream, printing the text.

    The loader interleaves log text and binary, so a blob can arrive in the
    middle of a line. Text before a blob is printed as it is found; the blob
    goes to on_blob. Returns the bytes that could not be interpreted yet.
    """
    while True:
        idx = buffer.find(BLOB_MAGIC)
        if idx == -1:
            # No blob magic in sight, so everything buffered is text. Emit and flush.
            if buffer:
                emit(buffer, raw)
            return b""

        if idx > 0:
            emit(buffer[:idx], raw)
            buffer = buffer[idx:]

        if len(buffer) < len(BLOB_MAGIC) + 4:
            return b""  # length field not here yet
        (length,) = struct.unpack("<I", buffer[len(BLOB_MAGIC):len(BLOB_MAGIC) + 4])
        total = len(BLOB_MAGIC) + 4 + length
        if len(buffer) < total:
            return b""  # payload not all here yet
        on_blob(buffer[len(BLOB_MAGIC) + 4:total])
        buffer = buffer[total:]


def receive(sock, raw=False, save_dir=None):
    """Stream output until the loader closes the connection."""
    buffer = b""
    blobs = []

    def on_blob(payload):
        blobs.append(payload)
        if save_dir:
            import os
            name = os.path.join(save_dir, f"blob-{len(blobs):03d}.bin")
            with open(name, "wb") as f:
                f.write(payload)
            print(paint(f"[*] blob: {len(payload)} bytes -> {name}", 35))
        else:
            head = payload[:32]
            print(paint(f"[*] blob: {len(payload)} bytes | "
                        f"{head.hex(' ')}", 35))
        sys.stdout.flush()

    while True:
        readable, _, _ = select.select([sock], [], [], 1.0)
        if not readable:
            continue
        try:
            chunk = sock.recv(4096)
        except OSError as exc:
            print(paint(f"[-] receive error: {exc}", 31))
            break
        if not chunk:
            break
        buffer += chunk
        buffer = frame_blobs(buffer, on_blob, raw=raw)

    if buffer:
        emit(buffer, raw)  # trailing partial line

    # A payload's last log lines can still be in flight when the loader closes
    # its end. Returning the instant recv() reports EOF dropped the tail of
    # every run -- the e2e test lost "--- payload done ---" and the status line
    # most of the time. Drain until the socket is genuinely dry.
    sock.settimeout(0.25)
    for _ in range(8):
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, TimeoutError, OSError):
            break
        if not chunk:
            break
        buffer += chunk
        buffer = frame_blobs(buffer, on_blob, raw=raw)
    if buffer:
        emit(buffer, raw)

    return blobs


def build_frame(data, args):
    """Build the wire frame for a payload, with argv when present.

    Without arguments this is the original simple shape, so a plain
    `send.py host port payload.js` is unchanged on the wire.

    With arguments the size field is the ARGV_MAGIC opcode and the body is
        u32 argc | (u32 len | bytes)* | u64 srclen | source
    which is necessary because the PS5 system browser has no address bar: argv
    cannot ride in on the page URL, so it has to come over the socket.
    """
    if not args:
        return struct.pack("<Q", len(data)) + data

    out = bytearray()
    out += struct.pack("<Q", ARGV_MAGIC)
    out += struct.pack("<I", len(args))
    for a in args:
        raw = a.encode("utf-8")
        out += struct.pack("<I", len(raw))
        out += raw
    out += struct.pack("<Q", len(data))
    out += data
    return bytes(out)


def send_file(host, port, path, raw=False, save_dir=None, args=None):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) > 512 * 1024:
        print(paint(f"[-] payload is {len(data)} bytes, over the 512 KiB limit", 31))
        return 1

    frame = build_frame(data, args or [])

    with socket.create_connection((host, port), timeout=30) as sock:
        sock.sendall(frame)
        extra = f" with {len(args)} arg(s)" if args else ""
        print(paint(f"[+] sent {len(data)} bytes from {path} to "
                    f"{host}:{port}{extra}", 32), flush=True)
        receive(sock, raw=raw, save_dir=save_dir)
    return 0


def send_command(host, port, command):
    with socket.create_connection((host, port), timeout=30) as sock:
        sock.sendall(struct.pack("<Q", COMMAND_MAGIC) + struct.pack("B", command))
        receive(sock)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="send.py",
        description="Send a .js payload to the PS5 WebKit Loader.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Protocol")[0],
    )
    p.add_argument("host", help="PS5 IP address")
    p.add_argument("port", type=int, help="loader port (default 9027)")
    p.add_argument("payload", nargs="?", help="path to a .js payload")
    p.add_argument("--status", action="store_true",
                   help="ask the loader for a status line")
    p.add_argument("--disconnect", action="store_true",
                   help="ask the loader to drop the connection")
    p.add_argument("--list", action="store_true",
                   help="reserved: list loaded payloads")
    p.add_argument("--raw", action="store_true",
                   help="print bytes exactly as received, no colouring")
    p.add_argument("--save-blobs", metavar="DIR", default=None,
                   help="write received binary blobs into DIR")
    p.add_argument("--arg", action="append", default=[], metavar="VALUE",
                   help="pass VALUE to the payload as api.args[i]. Sent over "
                        "the socket, since the PS5 browser has no URL bar.")
    args = p.parse_args(argv)

    if args.status:
        return send_command(args.host, args.port, CMD_STATUS)
    if args.disconnect:
        return send_command(args.host, args.port, CMD_DISCONNECT)
    if args.list:
        return send_command(args.host, args.port, CMD_LIST)
    if not args.payload:
        p.error("a payload path is required (or use --status/--disconnect/--list)")
    if not os.path.exists(args.payload):
        print(paint(f"[-] no such file: {args.payload}", 31))
        return 1

    try:
        return send_file(args.host, args.port, args.payload,
                         raw=args.raw, save_dir=args.save_blobs,
                         args=args.arg or None)
    except OSError as exc:
        print(paint(f"[-] cannot reach {args.host}:{args.port} -> {exc}", 31))
        print(paint("    Is the loader running, and is the port right?", 2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
