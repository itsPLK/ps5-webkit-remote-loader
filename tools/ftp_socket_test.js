// Offline regressions for PS5 WebKit socket and directory syscall refusals.
// Simulates sockets in memory; never opens a host network socket.
// Run: node tools/ftp_socket_test.js
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { int64 } from "../src/utils/int64.js";

const source = readFileSync(new URL("../payloads/ftp_server.js", import.meta.url), "utf8");
const entry = new Function(source)();
const rv = (n = 0) => new int64(n, 0);
const fail = () => new int64(0xffffffff, 0xffffffff);
const failed = (v) => v.low === 0xffffffff || v.hi === 0xffffffff;

function fixture(failNonblockingAt = 0, listing = null) {
  const pointer = (buffer, low = 0) => ({ buffer, low, hi: 0,
    add32(offset) { return pointer(buffer, low + offset); } });
  const errnoMemory = Buffer.alloc(8);
  const codeMemory = Buffer.alloc(0x4000);
  let mapped = false, writableMapped = false, protection = 5, unmaps = 0, inRawCall = false;
  const rawCalls = [];
  const memory = (a) => {
    if (a.buffer) return a;
    if (a.hi === 0x20) {
      const writable = a.low >= 0x30000;
      assert.equal(writable ? writableMapped : mapped, true, "mapping must remain live");
      return pointer(codeMemory, a.low - (writable ? 0x30000 : 0x20000));
    }
    assert.equal(a.hi, 9, "preserve the high dword of the worker TLS pointer");
    return pointer(errnoMemory, a.low - 0x11000);
  };
  const p = {
    malloc(n) { return pointer(Buffer.alloc(n + 1000)); },
    read1(a) { a = memory(a); return a.buffer.readUInt8(a.low); },
    read2(a) { a = memory(a); return a.buffer.readUInt16LE(a.low); },
    read4(a) { a = memory(a); return a.buffer.readUInt32LE(a.low); },
    read8(a) { return new int64(this.read4(a), this.read4(a.add32(4))); },
    write1(a, n) { if (a.hi === 0x20) assert.ok(a.low >= 0x30000, "write helper only through RW alias"); a = memory(a); a.buffer.writeUInt8(n & 255, a.low); },
    write2(a, n) { a = memory(a); a.buffer.writeUInt16LE(n & 65535, a.low); },
    write4(a, n) { a = memory(a); a.buffer.writeUInt32LE(n >>> 0, a.low); },
  };
  const descriptors = new Map();
  let nextFD = 0, nbioCalls = 0, fcntlCalls = 0, accepted = false, controlFD;
  let input = Buffer.from(listing?.mixedPaths
    ? "CWD /mnt/usb0\r\nEPSV\r\nLIST\r\nCWD /data\r\nEPSV\r\nLIST\r\nCWD /mnt/disc\r\nEPSV\r\nLIST\r\nQUIT\r\n" : listing
    ? "CWD /data\r\nEPSV\r\nLIST\r\nEPSV\r\nNLST\r\nQUIT\r\n"
    : "PASV\r\nEPSV\r\nPORT 127,0,0,1,195,80\r\nQUIT\r\n");
  let wire = "";
  const logs = [], directoryCalls = [], dataWrites = [];
  let resolutions = 0, errnoCalls = 0, batches = 0;
  const allocate = () => {
    const fd = nextFD++; descriptors.set(fd, { nonblocking: false }); return fd;
  };
  function address(ptr, port) {
    ptr.buffer.fill(0, ptr.low, ptr.low + 16);
    p.write1(ptr.add32(1), 2);
    p.write1(ptr.add32(2), port >>> 8); p.write1(ptr.add32(3), port & 255);
    p.write1(ptr.add32(4), 127); p.write1(ptr.add32(7), 1);
  }
  async function syscall(nr, ...args) {
    const [fd, arg, size] = args;
    const socket = descriptors.get(fd);
    switch (nr) {
      case 20: return rv(4242);
      case 24: return rv(listing?.uid || 0);
      case 585: return rv(listing?.sandbox || 0);
      case 533: {
        assert.deepEqual(args, [0, 0x4000, 7]);
        if (!listing.raw || listing.jitFailure) return fail();
        const jit = allocate(); descriptors.get(jit).role = "JIT RX"; return rv(jit);
      }
      case 534: {
        assert.equal(socket.role, "JIT RX"); assert.equal(arg, 3);
        if (listing.aliasFailure) return fail();
        const alias = allocate(); descriptors.get(alias).role = "JIT RW"; return rv(alias);
      }
      case 477: {
        const role = descriptors.get(args[4]).role;
        const writable = role === "JIT RW";
        assert.deepEqual(args, [0, 0x4000, writable ? 3 : 5, 1, args[4], 0]);
        if (writable ? listing.writeMapFailure : listing.execMapFailure) return fail();
        assert.equal(writable ? writableMapped : mapped, false);
        if (writable) writableMapped = true; else mapped = true;
        return new int64(writable ? 0x30000 : 0x20000, 0x20);
      }
      case 73:
        assert.equal(fd.hi, 0x20);
        assert.equal(arg, 0x4000);
        if (fd.low === 0x20000) { assert.equal(mapped, true); mapped = false; }
        else { assert.equal(fd.low, 0x30000); assert.equal(writableMapped, true); writableMapped = false; }
        unmaps++; return rv();
      case 591:
        resolutions++;
        assert.ok(fd === 0x2001 || fd === 1);
        assert.equal(arg.buffer.toString("utf8", arg.low, arg.buffer.indexOf(0, arg.low)), "__error");
        if (listing.resolveFailure || (listing.handleOneOnly && fd === 0x2001)) return fail();
        p.write4(size, 0x10000); p.write4(size.add32(4), listing.invalidSymbol ? 0xffff8000 : 8); return rv();
      case 188:
      case 189:
        arg.buffer.fill(0, arg.low, arg.low + 120);
        p.write2(arg.add32(8), 0o40755); return rv();
      case 5: {
        assert.ok(listing);
        const path = fd.buffer.toString("utf8", fd.low, fd.buffer.indexOf(0, fd.low));
        assert.ok(listing.mixedPaths ? ["/data", "/mnt/usb0", "/mnt/disc"].includes(path) : path === "/data");
        assert.equal(arg, 0, "directory opens match the reference's O_RDONLY, without O_NONBLOCK");
        const opened = allocate();
        descriptors.get(opened).entryIndex = 0;
        descriptors.get(opened).path = path;
        return rv(opened);
      }
      case 272:
      case 196: {
        assert.ok(listing);
        assert.equal(size, 65536, "directory read buffer must be 64 KiB for PS5 internal partitions");
        directoryCalls.push(nr);
        if (listing.mixedPaths && socket.path === "/data") {
          errnoMemory.writeUInt32LE(13); return fail();
        }
        if (inRawCall && listing.rawDirectoryErrno) {
          errnoMemory.writeUInt32LE(listing.rawDirectoryErrno);
          return fail();
        }
        if (nr === 272 && (listing.rejectGetdents ||
            (listing.rejectAfterFirst && socket.entryIndex > 0))) {
          errnoMemory.writeUInt32LE(listing.getdentsErrno || 78);
          return fail();
        }
        if (nr === 196) {
          assert.equal(args.length, 4, "getdirentries needs the base offset pointer");
          const base = args[3];
          assert.equal(base.low % 8, 0);
          if (socket.entryIndex === 0) {
            assert.equal(p.read4(base), 0); assert.equal(p.read4(base.add32(4)), 0);
          }
          // This output must not overlap the stat buffer or socket scratch.
          p.write4(base, socket.entryIndex); p.write4(base.add32(4), 1);
          if (listing.rejectGetdirentries) {
            errnoMemory.writeUInt32LE(listing.getdirentriesErrno || 13);
            return fail();
          }
        }
        if (listing.malformed) { arg.buffer.fill(0, arg.low, arg.low + 8); return rv(8); }
        const names = [".", "..", "folder", "caf\u00e9 file.txt"];
        if (socket.entryIndex === names.length) return rv();
        // One entry per read exercises repeated reads and a mid-list fallback.
        const name = Buffer.from(names[socket.entryIndex++]);
        const length = (8 + name.length + 1 + 3) & ~3;
        assert.ok(length <= size);
        arg.buffer.fill(0, arg.low, arg.low + length);
        p.write4(arg, socket.entryIndex);
        p.write2(arg.add32(4), length); p.write1(arg.add32(7), name.length);
        name.copy(arg.buffer, arg.low + 8);
        return rv(length);
      }
      case 97: return rv(allocate());
      case 92:
        // Reproduce the reported hardware behavior; the old payload stops here.
        fcntlCalls++;
        return arg === 3 ? rv(2) : fail();
      case 105:
        assert.equal(arg, 0xffff);
        if (size === 0x1200) {
          nbioCalls++;
          assert.equal(args[4], 4);
          assert.equal(p.read4(args[3]), 1);
          if (nbioCalls === failNonblockingAt) return fail();
          socket.nonblocking = true;
        } else assert.equal(size, 4, "unexpected socket option");
        return rv();
      case 104:
      case 106:
        assert.equal(socket.nonblocking, true); return rv();
      case 209: {
        assert.equal(arg, 1); assert.equal(size, 0, "poll must be nonblocking");
        const target = descriptors.get(p.read4(fd));
        assert.equal(target.nonblocking, true);
        const events = p.read2(fd.add32(4));
        p.write2(fd.add32(6), events); return rv(1);
      }
      case 30: {
        assert.equal(socket.nonblocking, true);
        if (fd === 0) { assert.equal(accepted, false); accepted = true; }
        else assert.ok(listing, "unexpected data connection");
        address(arg, 49151); p.write4(size, 16);
        const incoming = allocate();
        if (fd === 0) controlFD = incoming;
        return rv(incoming);
      }
      case 32:
        address(arg, 49152 + fd); p.write4(size, 16); return rv();
      case 29: {
        assert.equal(socket.nonblocking, true);
        assert.equal(args[3], 0x80);
        const count = Math.min(size, input.length, 13);
        input.copy(arg.buffer, arg.low, 0, count); input = input.subarray(count);
        return rv(count);
      }
      case 133: {
        assert.equal(socket.nonblocking, true);
        assert.equal(args[3], 0x20080);
        const count = Math.min(size, 17);
        const output = arg.buffer.toString("utf8", arg.low, arg.low + count);
        if (fd === controlFD) wire += output;
        else dataWrites.push(Buffer.from(arg.buffer.subarray(arg.low, arg.low + count)));
        return rv(count);
      }
      case 6:
        assert.equal(descriptors.delete(fd), true, "descriptor closed twice"); return rv();
      default: throw new Error(`unexpected syscall ${nr}`);
    }
  }
  const chain = { syscall };
  let gadgets;
  if (listing?.diagnostics) {
    gadgets = Object.fromEntries(["pop rax", "pop rdi", "mov rax, [rax]", "mov [rdi], eax"].map((key) => [key, key]));
    let ops = [];
    Object.assign(chain, {
      clear() { ops = []; },
      push(value) { ops.push(["push", value]); },
      add_syscall_ret(ptr, nr, ...args) { ops.push(["syscall", ptr, nr, args]); },
      write_result(ptr) { ops.push(["result", ptr]); },
      async call(symbol, nr, ...args) {
        if (symbol.hi === 0x20) {
          assert.equal(mapped, true); assert.equal(protection, 5);
          assert.equal(writableMapped, false, "unmap writable view before native execution");
          assert.equal(symbol.low, 0x20000);
          rawCalls.push(nr);
          if (nr === 20 && listing.rawProbeFailure) return new int64(-78, 0xffffffff);
          inRawCall = true;
          try {
            const value = await syscall(nr, ...args);
            return failed(value) ? new int64(-errnoMemory.readUInt32LE(0), 0xffffffff) : value;
          } finally { inRawCall = false; }
        }
        assert.equal(symbol.low, 0x10000);
        assert.equal(symbol.hi, 8, "preserve the high dword of the resolved function");
        errnoCalls++; return new int64(0x11000, listing.invalidErrno ? 0xffff8000 : 9);
      },
      async run() {
        batches++;
        let rax, rdi;
        for (let i = 0; i < ops.length; i++) {
          const [op, value, nr, args] = ops[i];
          if (op === "push") {
            if (value === "pop rax") rax = ops[++i][1];
            else if (value === "pop rdi") rdi = ops[++i][1];
            else if (value === "mov [rdi], eax") p.write4(rdi, typeof rax === "number" ? rax : rax.low);
            else if (value === "mov rax, [rax]") rax = p.read8(rax);
            else throw new Error(`unexpected test gadget ${value}`);
          } else if (op === "syscall") {
            assert.equal(errnoMemory.readUInt32LE(0), 0, "errno cleared inside batch");
            rax = await syscall(nr, ...args);
            p.write4(value, rax.low); p.write4(value.add32(4), rax.hi);
          } else {
            assert.equal(op, "result");
            p.write4(value, rax.low); p.write4(value.add32(4), rax.hi);
          }
        }
        // Simulate another worker call clobbering TLS errno before JS resumes.
        // The reply must still use the copy taken immediately after the syscall.
        errnoMemory.writeUInt32LE(99);
      },
    });
  }
  return {
    api: { p, int64, args: [], fw: "PS5 fixture", chain, gadgets,
      isFailure: failed, describe: () => "0xFFFFFFFF (-1)",
      setPayloadTimeout(ms) { assert.equal(ms, 0); },
      async log(message) { logs.push(message); } },
    inspect: () => ({ descriptors, nbioCalls, fcntlCalls, wire, logs, directoryCalls, resolutions, errnoCalls, batches,
      mapped, writableMapped, protection, unmaps, rawCalls, codeMemory,
      data: Buffer.concat(dataWrites).toString("utf8") }),
  };
}

{
  const test = fixture();
  await entry(test.api);
  const state = test.inspect();
  assert.equal(state.fcntlCalls, 0);
  assert.equal(state.nbioCalls, 4, "listener, accepted client and two passive listeners configured");
  assert.match(state.wire, /220 WebKit Remote Loader/);
  assert.match(state.wire, /227 Entering Passive Mode \(127,0,0,1,192,2\)/);
  assert.match(state.wire, /229 Entering Extended Passive Mode \(\|\|\|49155\|\)/);
  assert.match(state.wire, /200 PORT command OK/);
  assert.match(state.wire, /221 Goodbye/);
  assert.equal(state.descriptors.size, 0);
  console.log("ok: startup, accepted sockets, PASV/EPSV, PORT and QUIT with fcntl refused");
}
for (const failAt of [1, 2]) {
  const test = fixture(failAt);
  await assert.rejects(entry(test.api), /setsockopt\(SO_NBIO=0x1200\) failed: 0xFFFFFFFF/);
  assert.equal(test.inspect().descriptors.size, 0);
  assert.equal(test.inspect().fcntlCalls, 0);
  console.log(`ok: nonblocking failure ${failAt} reports the native result and closes descriptors`);
}
{
  const test = fixture(3);
  await entry(test.api);
  assert.match(test.inspect().wire, /425 setsockopt\(SO_NBIO=0x1200\) failed/);
  assert.match(test.inspect().wire, /229 Entering Extended Passive Mode/);
  assert.match(test.inspect().wire, /221 Goodbye/);
  assert.equal(test.inspect().descriptors.size, 0);
  console.log("ok: failed passive listener is closed and control session survives");
}

for (const listing of [{}, { rejectGetdents: true }, { rejectAfterFirst: true }]) {
  const test = fixture(0, listing);
  await entry(test.api);
  const state = test.inspect();
  assert.match(state.wire, /250 Directory changed/);
  assert.equal((state.wire.match(/226 Transfer complete/g) || []).length, 2);
  assert.match(state.data, /folder\r\n/);
  assert.match(state.data, /caf\u00e9 file.txt\r\n/);
  assert.ok(state.data.endsWith("folder\r\ncaf\u00e9 file.txt\r\n"), "NLST returns only names");
  assert.doesNotMatch(state.data, /(?:^|\r\n)\.{1,2}\r\n/);
  assert.equal(state.directoryCalls.filter((nr) => nr === 196).length,
    listing.rejectGetdents ? 10 : listing.rejectAfterFirst ? 8 : 0);
  assert.equal(state.directoryCalls.filter((nr) => nr === 272).length,
    listing.rejectGetdents ? 2 : listing.rejectAfterFirst ? 4 : 10);
  assert.equal(state.fcntlCalls, 0);
  assert.equal(state.descriptors.size, 0);
  console.log(`ok: LIST/NLST with ${listing.rejectGetdents ? "getdents refused" : listing.rejectAfterFirst ? "getdents failing after a partial listing" : "getdents supported"}`);
}
for (const listing of [{ rejectGetdents: true, rejectGetdirentries: true },
    { rejectGetdents: true, malformed: true }]) {
  const test = fixture(0, listing);
  await entry(test.api);
  const state = test.inspect();
  if (listing.malformed) assert.match(state.wire, /451 Invalid directory entry/);
  else assert.match(state.wire, /451 Directory read failed for \/data: getdents\(272\)=0xFFFFFFFF \(-1\); errno unavailable \(missing [^)]*\), getdirentries\(196\)=0xFFFFFFFF \(-1\); errno unavailable \(missing [^)]*\); uid=0, sandbox=0/);
  assert.doesNotMatch(state.wire, /226 Transfer complete/);
  assert.match(state.wire, /221 Goodbye/);
  assert.equal(state.descriptors.size, 0);
  console.log(`ok: ${listing.malformed ? "malformed alternate directory entries" : "both directory syscalls refused"} report failure and preserve the control session`);
}

for (const listing of [
  { diagnostics: true },
  { diagnostics: true, rejectGetdents: true },
  { diagnostics: true, rejectGetdents: true, rejectGetdirentries: true },
  { diagnostics: true, rejectGetdents: true, rejectGetdirentries: true, getdirentriesErrno: 14, uid: 1000, sandbox: 1 },
  { diagnostics: true, resolveFailure: true, rejectGetdents: true, rejectGetdirentries: true },
  { diagnostics: true, invalidSymbol: true, rejectGetdents: true, rejectGetdirentries: true },
  { diagnostics: true, invalidErrno: true, rejectGetdents: true, rejectGetdirentries: true },
  { diagnostics: true, handleOneOnly: true, rejectGetdents: true, rejectGetdirentries: true },
]) {
  const test = fixture(0, listing);
  await entry(test.api);
  const state = test.inspect();
  assert.equal(state.resolutions, listing.resolveFailure || listing.handleOneOnly ? 2 : 1, "try libkernel handles once per service");
  const unavailable = listing.resolveFailure || listing.invalidSymbol || listing.invalidErrno;
  assert.equal(state.errnoCalls, listing.resolveFailure || listing.invalidSymbol ? 0 : 1, "query the worker's TLS errno pointer once");
  assert.equal(state.batches, unavailable ? 0 : state.directoryCalls.length);
  if (listing.rejectGetdirentries && !unavailable) {
    assert.match(state.wire, /getdents\(272\)=0xFFFFFFFF \(-1\); errno=78 \(ENOSYS\)/);
    assert.match(state.wire, listing.getdirentriesErrno === 14
      ? /errno=14 \(EFAULT\); uid=1000, sandbox=1/
      : /errno=13 \(EACCES\); uid=0, sandbox=0/);
    assert.doesNotMatch(state.wire, /errno=99/);
  } else if (unavailable) {
    assert.match(state.wire, /errno unavailable/);
    if (listing.resolveFailure) {
      assert.match(state.wire, /dlsym\(__error\): handle 0x2001=0xFFFFFFFF \(-1\)\/handle 0x1=0xFFFFFFFF \(-1\)/);
      assert.ok(state.logs.some((line) => line.includes("could not resolve libkernel __error")));
    } else assert.match(state.wire, listing.invalidSymbol ? /invalid __error address 0xffff800000010000/ : /invalid errno pointer 0xffff800000011000/);
  } else assert.equal((state.wire.match(/226 Transfer complete/g) || []).length, 2);
  assert.match(state.wire, /221 Goodbye/);
  assert.equal(state.descriptors.size, 0);
  console.log(`ok: directory errno capture ${unavailable ? "reports why unavailable" : listing.rejectGetdirentries ? "preserves 64-bit pointers and original errors across worker return" : "keeps listings working with 64-bit pointers"}`);
}

for (const extra of [
  {},
  { rejectGetdents: true },
  { rejectGetdents: true, rejectGetdirentries: true },
  { rawDirectoryErrno: 9 },
  { jitFailure: true, rejectGetdents: true, rejectGetdirentries: true },
  { execMapFailure: true, rejectGetdents: true, rejectGetdirentries: true },
  { aliasFailure: true, rejectGetdents: true, rejectGetdirentries: true },
  { writeMapFailure: true, rejectGetdents: true, rejectGetdirentries: true },
  { rawProbeFailure: true, rejectGetdents: true, rejectGetdirentries: true },
]) {
  const test = fixture(0, { diagnostics: true, resolveFailure: true, raw: true, ...extra });
  await entry(test.api);
  const state = test.inspect();
  assert.equal(state.mapped, false, "native mapping released before loader returns");
  assert.equal(state.writableMapped, false, "writable alias released before loader returns");
  assert.equal(state.unmaps, extra.jitFailure || extra.execMapFailure ? 0
    : extra.aliasFailure || extra.writeMapFailure ? 1 : 2);
  assert.equal(state.descriptors.size, 0);
  assert.match(state.wire, /221 Goodbye/);
  if (extra.jitFailure || extra.execMapFailure || extra.aliasFailure || extra.writeMapFailure || extra.rawProbeFailure) {
    const why = extra.jitFailure ? /raw reader: jitshm_create failed/
      : extra.execMapFailure ? /raw reader: JIT RX mmap failed/
      : extra.aliasFailure ? /raw reader: jitshm_alias failed/
      : extra.writeMapFailure ? /raw reader: JIT RW mmap failed/
      : /raw reader: getpid probe failed \(errno=78\)/;
    assert.match(state.wire, why);
    assert.equal(state.rawCalls.length, extra.rawProbeFailure ? 1 : 0);
  } else {
    assert.equal(state.rawCalls[0], 20, "native reader tested with getpid before listing");
    assert.equal(state.rawCalls.filter((nr) => nr !== 20).length, state.directoryCalls.length);
    assert.equal(state.batches, 0, "raw error capture does not depend on TLS errno");
    assert.equal(state.errnoCalls, 0, "no unresolved library function is called");
    if (extra.rawDirectoryErrno) {
      assert.match(state.wire, /errno=9 \(EBADF\)/);
    } else if (extra.rejectGetdirentries) {
      assert.match(state.wire, /errno=78 \(ENOSYS\)/);
      assert.match(state.wire, /errno=13 \(EACCES\)/);
    } else assert.equal((state.wire.match(/226 Transfer complete/g) || []).length, 2);
  }
  console.log("ok: native directory reader captures errors or reports refusal, preserves session, and releases its page");
}

{
  const test = fixture(0, { diagnostics: true, resolveFailure: true, raw: true, mixedPaths: true });
  await entry(test.api);
  const state = test.inspect();
  assert.equal((state.wire.match(/226 Transfer complete/g) || []).length, 2);
  assert.equal((state.wire.match(/451 Directory read failed/g) || []).length, 1);
  assert.match(state.wire, /Directory read failed for \/data: .*errno=13 \(EACCES\).*uid=0, sandbox=0/);
  assert.match(state.wire, /221 Goodbye/);
  assert.equal(state.descriptors.size, 0);
  assert.equal(state.mapped, false); assert.equal(state.writableMapped, false);
  console.log("ok: USB/disc listings survive an internal path access refusal in the same root session");
}

// Check the actual firmware maps, including files with several keys per line.
const calls = new Function("return " + source.match(/const SYS = (\{[\s\S]*?\n  \});/)[1])();
for (const name of readdirSync(new URL("../offsets", import.meta.url)).filter((n) => n.endsWith(".js"))) {
  const offsets = readFileSync(new URL("../offsets/" + name, import.meta.url), "utf8");
  const map = new Function("return " + offsets.match(/(?:let|const) syscall_map = (\{[\s\S]*?\n\})/)[1])();
  for (const [call, nr] of Object.entries(calls)) assert.ok(map[nr], `${name} is missing ${call}`);
}
console.log("ok: updated FTP syscall requirements exist in every bundled firmware map");
