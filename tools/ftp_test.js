// Real FTP clients against the payload, with BSD syscalls emulated by Node.
// This checks protocol/filesystem behavior; the ROP chain requires a PS5.
// Run: node tools/ftp_test.js
import assert from "node:assert/strict";
import net from "node:net";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { int64 } from "../src/utils/int64.js";

const directory = fs.mkdtempSync(path.join(os.tmpdir(), "wkrl-ftp-"));
const source = fs.readFileSync(new URL("../payloads/ftp_server.js", import.meta.url), "utf8");
const entry = new Function(source)();
const ok = (n = 0) => new int64(n >>> 0, Math.floor(n / 0x100000000));
const failure = () => new int64(0xffffffff, 0xffffffff);
function pointer(buffer, offset = 0) {
  return { buffer, low: offset, hi: 0, add32(n) { return pointer(buffer, offset + n); } };
}
let allocations = 0;
const p = {
  malloc(size, type) { allocations++; assert.equal(type, 1); return pointer(Buffer.alloc(size + 1000)); },
  read1(a) { return a.buffer.readUInt8(a.low); },
  read2(a) { return a.buffer.readUInt16LE(a.low); },
  read4(a) { return a.buffer.readUInt32LE(a.low); },
  read8(a) { return new int64(this.read4(a), this.read4(a.add32(4))); },
  write1(a, n) { a.buffer.writeUInt8(n & 255, a.low); },
  write2(a, n) { a.buffer.writeUInt16LE(n & 65535, a.low); },
  write4(a, n) { a.buffer.writeUInt32LE(n >>> 0, a.low); },
};
const cstring = (a) => a.buffer.toString("utf8", a.low, a.buffer.indexOf(0, a.low));
const slice = (a, n) => a.buffer.subarray(a.low, a.low + n);
const fds = new Map();
let nextFD = 10;
const allocate = (item) => { const fd = nextFD++; fds.set(fd, item); return fd; };
let serverPort;
let connectFailures = 0, socketShortWrites = 0, fileShortWrites = 0;
let busy = false;

function streamItem(stream) {
  const item = { kind: "socket", stream, flags: 0, pending: Buffer.alloc(0), eof: false, connected: !stream.connecting, error: 0 };
  stream.on("data", (bytes) => { item.pending = Buffer.concat([item.pending, bytes]); });
  stream.on("end", () => { item.eof = true; });
  stream.on("connect", () => { item.connected = true; });
  stream.on("error", () => { item.error = 61; item.eof = true; });
  stream.on("close", () => { item.eof = true; });
  return item;
}
function fillAddress(a, port, host = "127.0.0.1") {
  slice(a, 16).fill(0);
  p.write1(a.add32(1), 2);
  p.write1(a.add32(2), port >>> 8); p.write1(a.add32(3), port & 255);
  host.split(".").forEach((v, i) => p.write1(a.add32(4 + i), Number(v)));
}
function stat(a, info) {
  slice(a, 120).fill(0);
  p.write2(a.add32(8), info.mode);
  // Different ctime deliberately catches the reference's incorrect +56 offset.
  const mtime = Math.floor(info.mtimeMs / 1000);
  p.write4(a.add32(40), mtime); p.write4(a.add32(56), 42);
  p.write4(a.add32(72), info.size); p.write4(a.add32(76), Math.floor(info.size / 0x100000000));
}
async function syscall(nr, ...args) {
  // The payload must never launch simultaneous ROP operations.
  assert.equal(busy, false, "overlapping syscalls");
  busy = true;
  try {
    const [fd, buf, len] = args;
    const item = fds.get(fd);
    switch (nr) {
      case 97: return ok(allocate({ kind: "socket", flags: 0, error: 0 }));
      case 92: throw new Error("PS5 WebKit sockets must not rely on fcntl(F_SETFL)");
      case 105:
        assert.equal(buf, 0xffff);
        if (len === 0x1200) {
          assert.equal(args[4], 4); assert.equal(p.read4(args[3]), 1);
          item.flags |= 4;
        } else assert.equal(len, 4);
        return ok();
      case 104:
        item.bindPort = p.read1(buf.add32(2)) * 256 + p.read1(buf.add32(3));
        return ok();
      case 106: {
        assert.ok(item.flags & 4, "listener must be nonblocking");
        item.accepts = [];
        item.server = net.createServer({ allowHalfOpen: true }, (stream) => {
          item.accepts.push(allocate(streamItem(stream)));
        });
        await new Promise((resolve, reject) => {
          item.server.once("error", reject);
          item.server.listen(item.bindPort, "127.0.0.1", resolve);
        });
        item.port = item.server.address().port;
        if (serverPort === undefined) serverPort = item.port;
        return ok();
      }
      case 30: {
        assert.ok(item.flags & 4);
        const accepted = item.accepts.shift();
        if (accepted === undefined) return failure();
        fillAddress(buf, fds.get(accepted).stream.remotePort);
        p.write4(len, 16); return ok(accepted);
      }
      case 32:
        fillAddress(buf, item.port || item.stream.localPort);
        p.write4(len, 16); return ok();
      case 209: {
        assert.equal(buf, 1); assert.equal(len, 0, "poll must not block the worker");
        const target = fds.get(p.read4(fd)), events = p.read2(fd.add32(4));
        let ready = 0;
        if (!target) ready = 32;
        else if (target.error) ready = 8;
        else if (target.server) { if (target.accepts.length) ready = 1; }
        else {
          if (target.pending?.length || target.eof) ready |= 1;
          if (target.eof) ready |= 16;
          if (target.connected && !target.stream.writableNeedDrain) ready |= 4;
        }
        ready &= events | 8 | 16 | 32;
        p.write2(fd.add32(6), ready); return ok(ready ? 1 : 0);
      }
      case 98: {
        assert.ok(item.flags & 4);
        const port = p.read1(buf.add32(2)) * 256 + p.read1(buf.add32(3));
        const host = Array.from({ length: 4 }, (_, i) => p.read1(buf.add32(4 + i))).join(".");
        const connected = streamItem(net.createConnection({ port, host, allowHalfOpen: true }));
        connected.flags = item.flags; fds.set(fd, connected);
        connectFailures++; return failure(); // Normal EINPROGRESS path.
      }
      case 118:
        assert.equal(len, 0x1007); p.write4(args[3], item.error); return ok();
      case 29: {
        assert.ok(item.flags & 4); assert.equal(args[3], 0x80);
        if (!item.pending.length) return item.eof ? ok() : failure();
        const count = Math.min(len, item.pending.length, 333);
        item.pending.copy(buf.buffer, buf.low, 0, count);
        item.pending = item.pending.subarray(count); return ok(count);
      }
      case 133: {
        assert.ok(item.flags & 4); assert.equal(args[3], 0x20080);
        const count = Math.min(len, 127);
        if (count < len) socketShortWrites++;
        item.stream.write(Buffer.from(slice(buf, count))); return ok(count);
      }
      case 5: {
        const pathname = cstring(fd), flags = buf;
        let native = fs.constants.O_RDONLY;
        if (flags & 1) native = fs.constants.O_WRONLY;
        if (flags & 0x200) native |= fs.constants.O_CREAT;
        if (flags & 0x400) native |= fs.constants.O_TRUNC;
        if (flags & 8) native |= fs.constants.O_APPEND;
        assert.ok((flags & 4) || flags === 0, "O_NONBLOCK expected for files; directories open with 0");
        const nativeFD = fs.openSync(pathname, native, len);
        const info = fs.fstatSync(nativeFD);
        return ok(allocate({ kind: "file", nativeFD, pathname, position: 0,
          entries: info.isDirectory() ? fs.readdirSync(pathname) : null, entryIndex: 0, append: !!(flags & 8) }));
      }
      case 188: stat(buf, fs.statSync(cstring(fd))); return ok();
      case 189: stat(buf, fs.fstatSync(item.nativeFD)); return ok();
      case 3: {
        if (item.pathname.endsWith("read-error")) return failure();
        const count = fs.readSync(item.nativeFD, buf.buffer, buf.low, Math.min(len, 777), item.position);
        item.position += count; return ok(count);
      }
      case 4: {
        if (item.pathname.endsWith("write-error")) return failure();
        const count = fs.writeSync(item.nativeFD, slice(buf, Math.min(len, 113)), 0, Math.min(len, 113), item.append ? null : item.position);
        if (count < len) fileShortWrites++;
        item.position += count; return ok(count);
      }
      case 478:
        assert.ok(buf instanceof int64, "64-bit seek must use the loader's int64");
        item.position = buf.low + buf.hi * 0x100000000; return ok(item.position);
      case 272: {
        if (item.pathname.endsWith("bad-dirents")) { slice(buf, 8).fill(0); return ok(8); }
        let cursor = 0;
        while (item.entryIndex < item.entries.length) {
          const name = Buffer.from(item.entries[item.entryIndex]);
          const size = (8 + name.length + 1 + 3) & ~3;
          if (cursor + size > len) break;
          const entry = buf.add32(cursor);
          slice(entry, size).fill(0); p.write2(entry.add32(4), size); p.write1(entry.add32(7), name.length);
          name.copy(entry.buffer, entry.low + 8);
          cursor += size; item.entryIndex++;
        }
        return ok(cursor);
      }
      case 136: fs.mkdirSync(cstring(fd), { mode: buf }); return ok();
      case 137: fs.rmdirSync(cstring(fd)); return ok();
      case 10: fs.unlinkSync(cstring(fd)); return ok();
      case 15: fs.chmodSync(cstring(fd), buf); return ok();
      case 128: fs.renameSync(cstring(fd), cstring(buf)); return ok();
      case 6:
        if (!item) throw new Error(`double close: ${fd}`);
        fds.delete(fd);
        if (item.server) {
          for (const accepted of item.accepts) { fds.get(accepted)?.stream.destroy(); fds.delete(accepted); }
          item.server.close();
        } else if (item.stream) item.stream.end();
        else if (item.kind === "file") fs.closeSync(item.nativeFD);
        return ok();
      default: throw new Error(`unimplemented test syscall: ${nr}`);
    }
  } catch (error) {
    // Filesystem refusals must appear as syscall failures, like the console.
    if (error.code && !(error instanceof assert.AssertionError)) return failure();
    throw error;
  } finally { busy = false; }
}

async function getPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
function client(port) {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", [new URL("./ftp_client_test.py", import.meta.url).pathname, String(port), directory],
      { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (data) => { stdout += data; });
    child.stderr.on("data", (data) => { stderr += data; });
    child.on("error", reject);
    child.on("close", (code) => code === 0 ? resolve(stdout) : reject(new Error(`${stdout}\n${stderr}`)));
  });
}

let timeout;
try {
  fs.writeFileSync(path.join(directory, "read-error"), "unreadable data");
  fs.mkdirSync(path.join(directory, "bad-dirents"));
  const port = await getPort();
  let ready;
  const listening = new Promise((resolve) => { ready = resolve; });
  let disabled = false;
  const running = entry({
    p, int64, fw: "test", args: [`port=${port}`, `path=${directory}`, "persist", "timeout=2"],
    chain: { syscall }, isFailure: (v) => v.low === 0xffffffff || v.hi === 0xffffffff,
    setPayloadTimeout(ms) { assert.equal(ms, 0); disabled = true; },
    async log(message) { if (message.startsWith("FTP listening")) ready(); },
  });
  const watchdog = new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error("FTP test timed out")), 30000); });
  await Promise.race([listening, running, watchdog]);
  assert.equal(serverPort, port);
  console.log("FTP: real ftplib + TCP, simulated BSD syscalls\n");
  console.log(await Promise.race([client(port), running.then(() => new Promise(() => {})), watchdog]));
  await Promise.race([running, watchdog]);
  assert.equal(disabled, true, "long-running FTP must disable loader watchdog");
  assert.equal(fds.size, 0, "all descriptors must be closed");
  assert.equal(allocations, 2, "native scratch allocations must stay bounded");
  assert.ok(socketShortWrites > 0 && fileShortWrites > 0, "partial writes must be exercised");
  assert.ok(connectFailures > 0, "active mode must exercise EINPROGRESS");
  console.log("ok: cleanup, bounded allocations, partial writes, nonblocking sockets, serialized syscalls");

  const baseAPI = {
    p, int64, fw: "test", args: [], chain: { syscall },
    isFailure: (v) => v.low === 0xffffffff || v.hi === 0xffffffff,
    setPayloadTimeout(ms) { assert.equal(ms, 0); }, async log() {},
  };
  for (const arg of ["port=0", "port=65536", "timeout=0", "timeout=3601", "ip=256.1.1.1", "unknown"]) {
    await assert.rejects(entry({ ...baseAPI, args: [arg] }));
    assert.equal(fds.size, 0);
  }
  await assert.rejects(entry({ ...baseAPI, args: [`path=${directory}/missing`] }), /stat failed/);
  assert.equal(fds.size, 0);
  console.log("ok: invalid configuration and startup failure cleanup");

  for (const quit of [true, false]) {
    serverPort = undefined;
    let notify;
    const ready = new Promise((resolve) => { notify = resolve; });
    const once = entry({ ...baseAPI, args: [`port=${await getPort()}`, `path=${directory}`, "timeout=2"],
      async log(message) { if (message.startsWith("FTP listening")) notify(); } });
    await Promise.race([ready, once, watchdog]);
    await new Promise((resolve, reject) => {
      const stream = net.createConnection({ host: "127.0.0.1", port: serverPort });
      stream.once("data", () => quit ? stream.write("QUIT\r\n") : stream.end());
      stream.on("data", () => {});
      stream.once("error", reject); stream.once("close", resolve);
    });
    await Promise.race([once, watchdog]);
    assert.equal(fds.size, 0);
    console.log(`ok: default mode returns after ${quit ? "QUIT" : "disconnect"}`);
  }

  serverPort = undefined;
  await assert.rejects(entry({ ...baseAPI, args: [`port=${await getPort()}`, `path=${directory}`, "timeout=1"] }), /timed out/);
  assert.equal(fds.size, 0);
  console.log("ok: accept timeout closes the FTP listener");

  const occupied = net.createServer();
  await new Promise((resolve) => occupied.listen(0, "127.0.0.1", resolve));
  try {
    await assert.rejects(entry({ ...baseAPI, args: [`port=${occupied.address().port}`, `path=${directory}`] }), /listen failed/);
    assert.equal(fds.size, 0);
    console.log("ok: listener setup failure closes descriptors");
  } finally { await new Promise((resolve) => occupied.close(resolve)); }
} finally {
  clearTimeout(timeout);
  for (const item of fds.values()) {
    item.server?.close(); item.stream?.destroy();
    if (item.nativeFD !== undefined) fs.closeSync(item.nativeFD);
  }
  // This directory contains only the temporary fixture created above.
  fs.rmSync(directory, { recursive: true, force: true });
}
