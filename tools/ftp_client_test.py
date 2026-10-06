#!/usr/bin/env python3
"""FTP wire tests launched by ftp_test.js; no external dependencies."""
import ftplib
import io
import os
import socket
import sys
import time

port, directory = int(sys.argv[1]), sys.argv[2]
checks = 0


def check(label, condition):
    global checks
    assert condition, label
    checks += 1
    print(f"  ok  {label}", flush=True)


def connect():
    ftp = ftplib.FTP()
    ftp.connect("127.0.0.1", port, timeout=5)
    ftp.login()
    return ftp


def error(ftp, command, code):
    try:
        ftp.sendcmd(command)
    except ftplib.Error as exc:
        check(command + " rejected", str(exc).startswith(str(code)))
    else:
        raise AssertionError(command + " should fail")


def retrieve(ftp, name, rest=None):
    result = io.BytesIO()
    ftp.retrbinary("RETR " + name, result.write, rest=rest)
    return result.getvalue()


ftp = connect()
check("initial PWD", ftp.pwd() == directory)
check("UNIX SYST", ftp.sendcmd("SYST").startswith("215 UNIX"))
check("NOOP", ftp.voidcmd("NOOP").startswith("200"))
check("features", "REST STREAM" in ftp.sendcmd("FEAT"))
check("UTF8 option", ftp.sendcmd("OPTS UTF8 ON").startswith("200"))
error(ftp, "TYPE invalid", 504)
error(ftp, "REST -1", 501)
error(ftp, "REST 9007199254740992", 501)
error(ftp, "PORT 127,0,0,1,256,0", 501)
error(ftp, "PORT 10,0,0,1,1,1", 501)
error(ftp, "RNTO no-source", 503)
error(ftp, "SIZE missing", 550)
error(ftp, "CWD missing", 550)
error(ftp, "RETR missing", 425)
error(ftp, "UNKNOWN", 502)
check("create directory", ftp.mkd("nested").endswith("/nested"))
ftp.cwd("nested")
ftp.mkd("child")
ftp.cwd("child")
ftp.cwd("..")
check("CWD .. moves one directory up", ftp.pwd() == directory + "/nested")
ftp.sendcmd("CDUP")
check("CDUP", ftp.pwd() == directory)

payload = bytes(range(256)) * 257 + b"binary\0\r\nend"
ftp.storbinary("STOR nested/file with spaces.bin", io.BytesIO(payload))
check("binary STOR + RETR with partial I/O", retrieve(ftp, "nested/file with spaces.bin") == payload)
check("SIZE uses its argument", ftp.size("nested/file with spaces.bin") == len(payload))
ftp.sendcmd("SITE CHMOD 0640 nested/file with spaces.bin")
check("SITE CHMOD octal", os.stat(directory + "/nested/file with spaces.bin").st_mode & 0o777 == 0o640)
check("resume RETR", retrieve(ftp, "nested/file with spaces.bin", 135) == payload[135:])
check("restart consumed", retrieve(ftp, "nested/file with spaces.bin") == payload)
ftp.storbinary("STOR nested/file with spaces.bin", io.BytesIO(b"new"))
check("STOR truncates", retrieve(ftp, "nested/file with spaces.bin") == b"new")
ftp.storbinary("APPE nested/file with spaces.bin", io.BytesIO(b"append"))
check("APPE appends", retrieve(ftp, "nested/file with spaces.bin") == b"newappend")
ftp.storbinary("STOR nested/file with spaces.bin", io.BytesIO(b"XY"), rest=2)
check("REST + STOR overwrites at offset", retrieve(ftp, "nested/file with spaces.bin") == b"neXYppend")
ftp.storbinary("STOR empty", io.BytesIO(b""))
check("empty file transfer", retrieve(ftp, "empty") == b"")

# Verify a full 64-bit lseek without allocating a large file.
large = directory + "/sparse"
with open(large, "wb") as handle:
    handle.seek(0x100000000 + 19)
    handle.write(b"tail")
check("SIZE >4GiB", ftp.size("sparse") == 0x100000000 + 23)
check("REST >4GiB", retrieve(ftp, "sparse", 0x100000000 + 19) == b"tail")
os.utime(directory + "/empty", (1700000000, 1700000000))
check("MDTM uses mtime", ftp.sendcmd("MDTM empty") == "213 20231114221320")
rows = []
ftp.retrlines("LIST nested", rows.append)
check("LIST path and permissions", any(row.startswith("-rw-r-----") and row.endswith("file with spaces.bin") for row in rows))
check("NLST names", "file with spaces.bin" in ftp.nlst("nested"))

# EPSV advertises the actual ephemeral listener port.
response = ftp.sendcmd("EPSV")
epsv_port = int(response.split("(|||")[1].split("|")[0])
data = socket.create_connection(("127.0.0.1", epsv_port), timeout=5)
ftp.sendcmd("TYPE I")
check("EPSV preliminary reply", ftp.sendcmd("RETR empty").startswith("150"))
check("EPSV EOF", data.recv(1) == b"")
data.close()
ftp.voidresp()

# Replacing PASV/PORT state must close the old listener.
old = ftp.makepasv()
new = ftp.makepasv()
try:
    abandoned = socket.create_connection(old, timeout=0.2)
except OSError:
    check("replaced PASV listener closed", True)
else:
    abandoned.close()
    raise AssertionError("old passive listener remains open")
ftp.sendcmd("ABOR")
error(ftp, "RETR empty", 425)

ftp.set_pasv(False)
ftp.storbinary("STOR active", io.BytesIO(payload))
check("active upload/download", retrieve(ftp, "active") == payload)
ftp.set_pasv(True)

for filename in ("read-error", "write-error"):
    try:
        if filename == "read-error":
            retrieve(ftp, filename)
        else:
            ftp.storbinary("STOR " + filename, io.BytesIO(b"fail"))
    except (ftplib.Error, OSError) as exc:
        check(filename + " fails without success reply", str(exc).startswith("451"))
    else:
        raise AssertionError(filename + " unexpectedly succeeded")
check("control survives file errors", ftp.sendcmd("NOOP").startswith("200"))
try:
    ftp.nlst("bad-dirents")
except ftplib.Error as exc:
    check("malformed dirent rejected", str(exc).startswith("451"))
else:
    raise AssertionError("malformed dirent was accepted")
ftp.rename("nested/file with spaces.bin", "nested/renamed.bin")
check("rename preserves contents", retrieve(ftp, "nested/renamed.bin") == b"neXYppend")
error(ftp, "RNFR missing", 550)
error(ftp, "RNTO bogus", 503)
ftp.delete("nested/renamed.bin")
ftp.rmd("nested/child")
ftp.rmd("nested")
check("delete and remove directory", not os.path.exists(directory + "/nested"))
ftp.quit()

# A later client gets independent cwd, REST and rename state.
ftp = connect()
check("persist accepts second client", ftp.pwd() == directory)
check("second client has no restart offset", retrieve(ftp, "active") == payload)
ftp.quit()

# Real command framing: fragmented UTF-8, CRLF, multiple commands in one read.
raw = socket.create_connection(("127.0.0.1", port), timeout=5)
lines = raw.makefile("rb")
check("raw welcome", lines.readline().startswith(b"220"))
raw.sendall(b"us")
time.sleep(0.02)
raw.sendall(b"er anonymous\r\nPASS test\r\nPWD\r")
time.sleep(0.02)
raw.sendall(b"\nNOOP\r\n")
check("fragmented and pipelined commands", [lines.readline()[:3] for _ in range(4)] == [b"331", b"230", b"257", b"200"])
utf8_name = "zażółć.txt"
with open(directory + "/" + utf8_name, "wb") as handle:
    handle.write(b"utf8")
encoded = ("SIZE " + utf8_name + "\r\n").encode()
split = encoded.index("ż".encode()) + 1
raw.sendall(encoded[:split])
time.sleep(0.02)
raw.sendall(encoded[split:])
check("fragmented UTF-8 pathname", lines.readline().startswith(b"213 4"))
raw.sendall(b"NOOP " + b"x" * 4097 + b"\r\n")
check("oversized command closes client", lines.readline().startswith(b"421"))
lines.close()
raw.close()

# Timeout abandoned data connections; leave control usable afterwards.
ftp = connect()
ftp.sendcmd("PASV")
try:
    ftp.sendcmd("LIST")
    ftp.voidresp()
except ftplib.Error as exc:
    check("abandoned passive transfer times out", str(exc).startswith("425"))
else:
    raise AssertionError("abandoned transfer did not time out")
check("control survives transfer timeout", ftp.sendcmd("NOOP").startswith("200"))
check("SITE STOP", ftp.sendcmd("SITE STOP").startswith("221"))
ftp.close()
print(f"\n{checks} FTP checks passed", flush=True)
