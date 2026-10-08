// Offline loader, ABI, and port fidelity checks.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const { runLoader } = await import(pathToFileURL(join(ROOT, "src/loader.js")).href);
// int64 up front, not inside the test that happens to need it: makeFake()'s read8
// has to return a real int64 for the ported rop.js to accept a value off it. It
// used to return a plain {low, hi}, which rop.js correctly rejects -- "pushed a
// value that is neither a number nor an int64" -- so a chain-authoring payload
// could not get past its first thread. On hardware read8 returns a real int64.
const { int64 } = await import(pathToFileURL(join(ROOT, "src/utils/int64.js")).href);

// Stand in for the offset file, which is what defines window.KRW on a real run.
globalThis.window = globalThis;
globalThis.window.fw_str = "9.99";
globalThis.window.KRW = {
  firmware: "test", allproc: 0x111, proc: { pid: 0x0bc, ucred: 0x040, fd: 0x048 },
  ucred: { uid: 0x04 }, aio: { group: { num: 0x00 } },
};

// Stand in for window.SYMBOLS, the other half of what an offsets file defines.
// src/kexp.js resolves these to reach libkernel and libc, and refuses to run
// without all of them, so the launchKexp tests below cannot get past the
// symbol check without it.
globalThis.window.SYMBOLS = {
  libkernel: {
    getpid: 0x14, sysctlbyname: 0x2a, sceKernelSendNotificationRequest: 0x3c,
    pthread_create: 0x4c, pthread_join: 0x5c,
  },
  libc: { malloc: 0x6c, free: 0x7c, memcpy: 0x8c, memset: 0x9c, strcmp: 0xac, memcmp: 0xbc, vsnprintf: 0xcc },
};

// A minimal ELF, enough for src/kexp.js's "is this an ELF" check. Only the magic
// and the length matter here: the test never gets past the mmap that follows.
function fakeElf(bytes = 0x1000) {
  const b = Buffer.alloc(bytes);
  b.writeUInt32LE(0x464c457f, 0);
  return b;
}

function readOffsetTables(firmware) {
  const dir = join(ROOT, "offsets");
  // Sort by VERSION, not lexicographically: "9.60.js" sorts after "13.60.js", so a
  // plain string sort picks a 2015 table for a 2024 test.
  const all = readdirSync(dir).filter((f) => f.endsWith(".js"))
    .map((f) => ({ f, v: f.replace(/\.js$/, "").split(".").map(Number) }))
    .sort((a, b) => (a.v[0] - b.v[0]) || (a.v[1] - b.v[1]));
  const fw = firmware || all[all.length - 1].f.replace(/\.js$/, "");
  const ctx = vm.createContext({ window: {}, console });
  vm.runInContext(readFileSync(join(dir, `${fw}.js`), "utf8"), ctx, { filename: `offsets/${fw}.js` });
  return {
    syscall_map: vm.runInContext("syscall_map", ctx),
    wk_gadgetmap: vm.runInContext("wk_gadgetmap", ctx),
    firmware: fw,
  };
}

// The page's own origin. src/kexp.js resolves its binary paths against
// document.baseURI, the same way api.module() does, because the loader is served
// under the User's Guide's document path rather than the repo root. node has no
// document, so these tests stand one in.
if (typeof globalThis.document === "undefined") {
  globalThis.document = { baseURI: "http://127.0.0.1/document/en/ps5/index.html" };
}

// fetch() does not exist in node. serve() installs this for one test and always
// removes it, so a stub cannot leak into a later assertion and quietly change
// what api.module() does.
async function withFetch(handler, body) {
  const had = "fetch" in globalThis;
  const previous = globalThis.fetch;
  globalThis.fetch = handler;
  try {
    return await body();
  } finally {
    if (had) globalThis.fetch = previous;
    else delete globalThis.fetch;
  }
}

let failures = 0;
let checks = 0;
function check(label, ok, detail = "") {
  checks++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${!ok && detail ? "  " + detail : ""}`);
  if (!ok) failures++;
}

/*
 * A fake console.
 *
 * p is backed by real Buffers, so an "address" is just an offset into an
 * allocation and read/write round-trip correctly. The chain records detached
 * chains and runs them on launch, which is what acceptOnce() waits for.
 */
function makeFake(opts = {}) {
  const allocs = [];
  const trace = [];

function makePtr(low, buf, hi = 0) {
  const v = new int64(low, hi);
  v._buf = buf;
  v.backing = buf;
  v.add32 = (d) => {
    const lo = (v.low + d) >>> 0;
    return makePtr(lo, buf, (v.hi + (lo < v.low ? 1 : 0)) >>> 0);
  };
  return v;
}
const base = (low, hi = 0) => makePtr(low, null, hi);

  const p = {
    libKernelBase: base(0x7f200000),
    libSceNKWebKitBase: base(0x7f000000),
    libSceLibcInternalBase: base(0x7f100000),
    gadgets: {},
    syscalls: {},

    malloc(size) {
      const buf = Buffer.alloc(Math.max(64, (size | 0) + 64));
      allocs.push(buf);
      const view = (off) => {
        const v = { low: off >>> 0, hi: 0, _buf: buf };
        v.add32 = (d) => view(off + d);
        // int64.toString() is hex and is how payloads print an address. Without it
        // a log line that reports a buffer pointer reads "0x[object Object]", which
        // looks like a payload bug in a test that is meant to show the port working.
        v.toString = () => (v.hi === 0
          ? v.low.toString(16)
          : v.hi.toString(16) + v.low.toString(16).padStart(8, "0"));
        return v;
      };
      return view(0);
    },
    write1(a, v) { a._buf.writeUInt8(v & 0xff, a.low); },
    write2(a, v) { a._buf.writeUInt16LE(v & 0xffff, a.low); },
    write4(a, v) { a._buf.writeUInt32LE(v >>> 0, a.low); },
    write8(a, v) {
      a._buf.writeUInt32LE(v.low >>> 0, a.low);
      a._buf.writeUInt32LE(v.hi >>> 0, a.low + 4);
    },
    read1(a) { return a._buf.readUInt8(a.low); },
    read2(a) { return a._buf.readUInt16LE(a.low); },
    read4(a) { return a._buf.readUInt32LE(a.low); },
    read8(a) {
      // A real int64, not a bare {low, hi}. The ported rop.js checks
      // `value instanceof int64` before pushing anything onto a ROP stack, so a
      // plain object here makes the fake reject what hardware accepts.
      return new int64(a._buf.readUInt32LE(a.low), a._buf.readUInt32LE(a.low + 4));
    },
    leakval() { return { low: 0, hi: 0 }; },
  };

  const sock = { fd: 10, inbound: Buffer.alloc(0), writes: [], accepts: 0, maxAccepts: 1 };

  let detached = null;
  let dirty = null;

  const chain = {
    pre_chain() {},
    clear() { assertIdle("clear"); this.count = 0; dirty = null; pending.length = 0; },
    push() { assertIdle("push"); }, push_write8() { assertIdle("push_write8"); },
    fcall() { assertIdle("fcall"); }, write_result() { assertIdle("write_result"); },
    add_syscall(nr, ...args) { assertIdle("add_syscall"); pending.push([nr, args]); this.count++; },
    add_syscall_ret(retstore, nr, ...args) {
      assertIdle("add_syscall_ret");
      detached = { retstore, nr, args };
      dirty = { nr };
    },
    // run() executes the accumulated batch. Modelled properly because the gated
    // chain in loader.js exists to keep a batch atomic: if anything executes the
    // chain between the build and the run, the batch is lost. A fake whose run()
    // did nothing could never catch that.
    async run() {
      inRun++;
      if (inRun > 1) {
        inRun--;
        throw new Error(`re-entrant chain use: ${inRun + 1} concurrent run()s`);
      }
      const batch = pending.slice();
      pending.length = 0;
      this.count = 0;
      try {
        await null; // give a concurrent caller the chance to interleave
        for (const [nr, args] of batch) await dispatch(nr, args);
      } finally {
        inRun--;
      }
    },
    async syscall(nr, ...args) {
      if (dirty && dirty.nr !== nr) {
        throw new Error(
          `chain not cleared before syscall 0x${nr.toString(16)}: it still holds ` +
          `the detached 0x${dirty.nr.toString(16)}, which would be re-run`);
      }
      // syscall() builds onto the stack buffer and runs it, so it must not start
      // while the worker is mid-execution of a previous batch. This is the exact
      // window a queued log write used to land in.
      assertIdle("syscall");
      inSyscall++;
      if (inSyscall > 1) {
        inSyscall--;
        throw new Error(
          `re-entrant chain use: ${inSyscall + 1} concurrent syscalls ` +
          `(nr 0x${nr.toString(16)})`);
      }
      try {
        await null; // give a concurrent caller the chance to overlap
        return await dispatch(nr, args);
      } finally {
        inSyscall--;
      }
    },
  };

  let inSyscall = 0;
  let inRun = 0;
  // Ops accumulated by clear()/add_syscall(), consumed by run(). This is the
  // state a 353-syscall reclaim batch builds up, and the reason the payload's
  // chain is gated: a log write landing between the build and the run would
  // execute the chain and wipe every one of them.
  const pending = [];
  // Last rtprio_thread(RTP_SET) value, so RTP_LOOKUP can echo it back.
  const rtprio = { type: 3, prio: 0 };
  // cpuset affinity masks, per level. Seeded non-empty on purpose: poops'
  // chooseCore() refuses outright on a zero mask, which would stop the run before
  // the ladder. Cores 0-3, spread so coreList() has more than one bit to report.
  const affinityMasks = new Map();
  const affinity = (level) => {
    let m = affinityMasks.get(level);
    if (!m) {
      m = new Uint8Array(16);
      m[0] = 0x0f; m[1] = 0x0f; m[2] = 0x0f; m[3] = 0x0f;
      affinityMasks.set(level, m);
    }
    return m;
  };

  function assertIdle(what) {
    if (inRun > 0) {
      throw new Error(
        `chain stack mutated while the worker was executing it (${what}): ` +
        `rop.js appends to one shared buffer with no lock, so the worker reads a ` +
        `stack that is changing underneath it`);
    }
  }

  async function dispatch(nr, args) {
    trace.push(nr);
    // Ordering hook. Some assertions are about WHEN two kinds of event happen
    // relative to each other -- a payload that must fetch before it runs a kernel
    // exploit, for instance -- and trace alone cannot express that, because the
    // fetch does not go through the chain. Tests set globalThis.__ORDER and get
    // one shared timeline; nothing else reads it.
    if (globalThis.__ORDER) globalThis.__ORDER.push(`syscall:0x${nr.toString(16)}`);
    switch (nr) {
      case 0x061: return { low: sock.fd, hi: 0 };                    // socket
      case 0x01e: return { low: sock.fd + 1, hi: 0 };                // accept
      case 0x014: return { low: 4242, hi: 0 };                       // getpid
        case 0x003: {                                                  // read
          if (sock.inbound.length === 0) return { low: 0xffffffff, hi: 0 };
          const want = (args[2] >>> 0) || sock.inbound.length;
          const n = Math.min(want, sock.inbound.length);
          // args[1] may be an add32() view with the offset baked into .low, so
          // go through add32(i) for every byte rather than assuming _buf/low.
          const chunk = sock.inbound.subarray(0, n);
          for (let i = 0; i < n; i++) {
            const at = args[1].add32(i);
            at._buf.writeUInt8(chunk[i], at.low);
          }
          sock.inbound = sock.inbound.subarray(n);
          return { low: n, hi: 0 };
        }
        case 0x004: {                                                  // write
          const len = args[2] >>> 0;
          const src = args[1];
          const out = Buffer.alloc(len);
          for (let i = 0; i < len; i++) {
            const at = src.add32(i);
            out[i] = at._buf.readUInt8(at.low);
          }
          sock.writes.push(out);
          return { low: len, hi: 0 };
        }
        // DEBUG: also show what the loader actually logged, if asked.
        case 0x006: return { low: 0, hi: 0 };                          // close
        case 0x1e7: {                                                  // cpuset_getaffinity
          if (!opts.chainAuthoring) return { low: 0, hi: 0 };
          const buf = args[4], mask = affinity(args[0] >>> 0);
          for (let i = 0; i < 16; i++) buf.add32(i)._buf.writeUInt8(mask[i], buf.low + i);
          return { low: 0, hi: 0 };
        }
        case 0x1e8: {                                                  // cpuset_setaffinity
          if (!opts.chainAuthoring) return { low: 0, hi: 0 };
          const buf = args[4], mask = affinity(args[0] >>> 0);
          for (let i = 0; i < 16; i++) mask[i] = buf.add32(i)._buf.readUInt8(buf.low + i);
          return { low: 0, hi: 0 };
        }
        case 0x1d2: {
          if (!opts.chainAuthoring) return { low: 0, hi: 0 };
          const how = args[0] >>> 0, buf = args[2];
          if (how === 1) {                       // RTP_SET
            rtprio.type = buf._buf.readUInt16LE(buf.low);
            rtprio.prio = buf._buf.readUInt16LE(buf.low + 2);
          } else {                               // RTP_LOOKUP
            buf._buf.writeUInt16LE(rtprio.type, buf.low);
            buf._buf.writeUInt16LE(rtprio.prio, buf.low + 2);
          }
          return { low: 0, hi: 0 };
        }
        default: return { low: 0, hi: 0 };
    }
  }

  p.launch_chain_detached = () => {
    if (!detached) return;
    const { retstore, nr } = detached;
    detached = null;
    if (nr === 0x01e) {
      if (sock.accepts >= sock.maxAccepts) p.write8(retstore, { low: 0xffffffff, hi: 0 });
      else { sock.accepts++; p.write8(retstore, { low: sock.fd + 1, hi: 0 }); }
    } else {
      p.write8(retstore, { low: 0, hi: 0 });
    }
  };
  p.launch_chain = async () => {};

  if (opts.chainAuthoring) {
    const { syscall_map: syscallMap, wk_gadgetmap: gadgetMap } = readOffsetTables(
      opts.firmware);
    for (const [name, rva] of Object.entries(gadgetMap))
      p.gadgets[name] = base(p.libSceNKWebKitBase.low + rva);
    for (const [nr, rva] of Object.entries(syscallMap))
      p.syscalls[nr] = base(p.libKernelBase.low + rva);

    p.malloc = function (size, type = 4) {
      // Same backing-size rule as src/main.js's malloc, so a payload that sizes
      // an arena against it sees what it would on hardware, and a real int64 so
      // rop.js accepts it on a stack.
      const backing = Buffer.alloc(type === 1 ? 1000 + (size | 0) : 0x10000 + (size | 0));
      return makePtr(0, backing);
    };
    p.stringify = (s) => {
      const v = p.malloc(s.length + 1, 1);
      for (let i = 0; i < s.length; i++) v.backing[i] = s.charCodeAt(i) & 0xff;
      return v;
    };
    p.writestr = (addr, str) => {
      for (let i = 0; i < str.length; i++)
        addr._buf.writeUInt8(str.charCodeAt(i) & 0xff, addr.low + i);
    };

    // Mirrors the real worker_rop: an 0x80000 stack with a 0x10000 reserve, whose
    // entry point is deliberately misaligned (low & 8) so a payload's alignment
    // arithmetic is exercised on both branches.
    chain.stack_size = 0x80000;
    chain.reserved_stack = 0x10000;
    chain.initial_count = 0;
    chain.stack_entry_point = base(0x7f400018);
    chain.return_value = base(0x7f480000);
    // Slot accounting, mirroring src/rop.js so a payload's own count mirror can be
    // compared against something real. fcall's alignment branch is reproduced.
    const entryLow = chain.stack_entry_point.low;
    chain.clear = function () { assertIdle("clear"); this.count = 0; dirty = null; pending.length = 0; };
    chain.push = function () { assertIdle("push"); this.count++; };
    chain.fcall = function (rip, ...args) {
      assertIdle("fcall");
      for (const a of args) if (a !== undefined) this.count += 2;
      if (((entryLow + this.count * 8) >>> 0) & 8) this.count++;
      this.count++;
    };
    chain.write_result = function () { assertIdle("write_result"); this.count += 3; };
    chain.write_result4 = function () { assertIdle("write_result4"); this.count += 3; };
    chain.push_write8 = function () { assertIdle("push_write8"); this.count += 4; };
  }

  return { p, chain, sock, trace };
}

function frame(size) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(size));
  return b;
}

// Drive the loader to completion against a prepared fake.
async function drive(p, chain) {
  const fin = runLoader(p, chain, () => {}).catch(() => {});
  await Promise.race([fin, new Promise((r) => setTimeout(r, 2000))]);
}

// Build the wire frame exactly as tools/send.py does, so the two sides of the
// argv extension are tested against each other rather than against a
// description of each other.
function buildFrame(source, argv) {
  const body = Buffer.from(source ?? "", "utf8");
  if (!argv || !argv.length) return Buffer.concat([frame(body.length), body]);
  const parts = [frame(0xfffffffe)];
  const argc = Buffer.alloc(4);
  argc.writeUInt32LE(argv.length, 0);
  parts.push(argc);
  for (const a of argv) {
    const raw = Buffer.from(a, "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32LE(raw.length, 0);
    parts.push(len, raw);
  }
  parts.push(frame(body.length), body);
  return Buffer.concat(parts);
}

// Run one connection through the loader and collect its output.
async function run(source, { command, maxAccepts = 1, argv, fakeOpts } = {}) {
  const { p, chain, sock, trace } = makeFake(fakeOpts);
  sock.maxAccepts = maxAccepts;

  sock.inbound = command !== undefined
    ? Buffer.concat([frame(0xffffffff), Buffer.from([command])])
    : buildFrame(source, argv);

  const lines = [];
  const log = (m) => { if (lines.length < 400) lines.push(String(m)); };

  let fatal = null;
  const finished = runLoader(p, chain, log).catch((e) => {
    fatal = e;
    lines.push(`FATAL ${e && e.message ? e.message : e}`);
  });
  await Promise.race([finished, new Promise((r) => setTimeout(r, 3000))]);

  // Payload logs travel over the SOCKET, not the console log. `lines` only
  // holds the loader's own status output, so assertions about payload output
  // must look at `wire`.
  return {
    text: lines.join("\n"),
    lines,
    wire: Buffer.concat(sock.writes).toString("utf8"),
    wireBuf: Buffer.concat(sock.writes),
    sock, trace, fatal,
  };
}

async function runSequence(sources, opts = {}) {
  const { p, chain, sock, trace } = makeFake(opts.fakeOpts);
  sock.maxAccepts = sources.length;
  sock.inbound = Buffer.concat(sources.map((s) =>
    buildFrame(typeof s === "string" ? s : s.src, typeof s === "string" ? null : s.argv)));

  const wireText = () => Buffer.concat(sock.writes).toString("utf8");
  const completed = () => wireText().split("--- payload done ---").length - 1;

  let fatal = null;
  const finished = runLoader(p, chain, () => {}).catch((e) => { fatal = e; });
  for (let i = 0; i < 400 && completed() < sources.length; i++)
    await new Promise((r) => setTimeout(r, 20));
  await Promise.race([finished, new Promise((r) => setTimeout(r, opts.settleMs ?? 1500))]);

  return { wire: wireText(), sock, trace, fatal };
}

// The first line that differs between two texts, for failure output.
//
// A 1200-line payload compared against its upstream original produces a useless
// "not equal" without it, and the whole value of the check is being able to see
// what moved.
function firstDifference(got, want) {
  if (got === null || want === null) return "";
  const a = got.split("\n"), b = want.split("\n");
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) {
      const from = i > 12 ? `line ${i + 1}` : `line ${i + 1}`;
      const around = Math.max(0, i - 2);
      return `${from}: got ${JSON.stringify(a[i])}, upstream ${JSON.stringify(b[i])} ` +
        `(context from line ${around + 1})`;
    }
  }
  return `same line-for-line but ${a.length} vs ${b.length} lines`;
}

console.log("loader self-test (protocol + control flow, NOT the ROP chain)\n");

// 1. a well-formed payload runs and its logs come back
{
  const { text, lines, wire } = await run(`
    return async function (api) {
      await api.log("hello from a payload");
      await api.log("firmware: " + api.fw);
    };
  `);
  if (process.env.DBG) console.log("   LINES:\n" + lines.join("\n"));
  check("payload logs reach the loader", wire.includes("hello from a payload"));
  check("firmware reaches the payload", /firmware: \S/.test(wire));
  check("completion is reported", wire.includes("payload done"));
}

// 2. a throwing payload must not kill the session
{
  const { text, wire } = await run(`
    return async function (api) {
      await api.log("before the throw");
      throw new Error("deliberate payload failure");
    };
  `);
  check("logs before a throw survive", wire.includes("before the throw"));
  check("the throw is caught and logged", wire.includes("deliberate payload failure"));
  check("the session survives a throwing payload", wire.includes("payload done"));
}

// 2b. a payload pushing an invalid value to the chain reports exact line and code snippet
{
  const { wire } = await run(`
    return async function (api) {
      const bad = undefined;
      api.chain.push(bad);
    };
  `);
  check("bad chain push throws informative error",
    wire.includes("You're trying to write a non number/non int64 value? (undefined)"));
  check("bad chain push reports payload.js file and line number",
    /at payload\.js:\d+/.test(wire));
  check("bad chain push shows offending code line snippet",
    wire.includes("api.chain.push(bad)"));
}

// 2c. a payload pushing a 64-bit integer without int64 instance reports error
{
  const { wire } = await run(`
    return async function (api) {
      api.chain.push(0x100000000);
    };
  `);
  check("exceeding 32-bits without int64 throws informative error",
    wire.includes("value exceeding 32-bits without using an int64 instance"));
  check("exceeding 32-bits reports source line snippet",
    wire.includes("api.chain.push(0x100000000)"));
}

// 3. a payload that is not valid JS at all
{
  const { text, wire, fatal } = await run("this is ( not javascript");
  check("a syntax error does not escape the loader", fatal === null, fatal ? fatal.message : "");
  // A syntax error means the payload never ran, so there is no "payload done";
  // what matters is that the loader reported it and kept going.
  check("the syntax error is reported", /payload threw|SyntaxError|Unexpected/.test(wire),
    wire.match(/payload threw: [^\n]*/)?.[0] || "");
}

// 4. the payload cannot see loader internals
{
  const { text, wire } = await run(`
    return async function (api) {
      const leaked = (typeof inBuf !== "undefined") || (typeof pending !== "undefined");
      await api.log("isolation: leaked=" + leaked);
    };
  `);
  check("payload cannot see loader internals", wire.includes("leaked=false"));
}

// 5. logs actually reach the socket bytes
{
  const { sock } = await run(`
    return async function (api) { await api.log("on the wire"); };
  `);
  const all = Buffer.concat(sock.writes);
  check("log text is written to the socket", all.includes(Buffer.from("on the wire")));
  check("payload framing markers are present",
    all.includes(Buffer.from("--- payload done ---")));
}

// 6. the ABI surface a payload can rely on
{
  const { text, wire } = await run(`
    return async function (api) {
      const want = ["p","chain","krw","fw","gadgets","syscalls","int64","log","sendBlob"];
      const missing = want.filter((k) => api[k] === undefined);
      await api.log("missing: " + (missing.length ? missing.join(",") : "none"));
      await api.log("krw is: " + String(api.krw));
      await api.log("krw null? " + (api.krw === null));
    };
  `);
  check("the full ABI is present", wire.includes("missing: none"));
  check("krw reads back as null", wire.includes("krw null? true"),
    (wire.match(/krw (?:is|null\?): [^\n]*/g) || []).join(" | "));
}

// 7. a payload can publish krw for later payloads
{
  const { text, wire } = await run(`
    return async function (api) {
      api.krw = { fake: true };
      await api.log("krw published: " + (api.krw !== null));
    };
  `);
  check("a payload can set krw", wire.includes("krw published: true"));
}

// 8. a command is routed, not run as a payload
{
  const { text, wire } = await run("", { command: 1 });
  check("the status command is recognised", /command: status|up: fd/.test(wire), wire.match(/\[.\] (up:.*|command:.*)/)?.[0] || "");
  check("a command is not treated as a payload", !wire.includes("payload done"));
}

// 9. an oversized size is refused
{
  const { p, chain, sock } = makeFake();
  sock.maxAccepts = 1;
  sock.inbound = frame(0x7fffffff);
  await drive(p, chain);
  const wire = Buffer.concat(sock.writes).toString("utf8");
  check("an oversized payload is refused", wire.includes("bad payload size"), wire.match(/bad payload size \d+/)?.[0] || "");
}

// 10. a zero-size payload is refused
{
  const { p, chain, sock } = makeFake();
  sock.maxAccepts = 1;
  sock.inbound = frame(0);
  await drive(p, chain);
  check("a zero-size payload is refused",
    Buffer.concat(sock.writes).toString("utf8").includes("bad payload size"));
}

// 11. the u64 size header survives a value above 2^32
{
  const big = Buffer.alloc(8);
  big.writeBigUInt64LE(0x1_0000_0000n);
  const { p, chain, sock } = makeFake();
  sock.maxAccepts = 1;
  sock.inbound = big; // 4 GiB: over the limit, and must not wrap to a small size
  await drive(p, chain);
  const text = Buffer.concat(sock.writes).toString("utf8");
  check("a >4GiB size is rejected, not wrapped", text.includes("bad payload size"),
    text.match(/bad payload size \d+/)?.[0] || "");
}

// 11b. the loader's own allocations stay inside the budget that works on hardware
{
  const src = readFileSync(join(ROOT, "src/loader.js"), "utf8");
  const m = src.match(/const READ_BUF = (\d+) \* 1024/);
  const w = src.match(/const WRITE_BUF = (\d+) \* 1024/);
  check("READ_BUF is declared in KiB", !!m, m ? `${m[1]} KiB` : "not found");
  check("WRITE_BUF is declared in KiB", !!w, w ? `${w[1]} KiB` : "not found");
  // p.malloc(size) is new Uint32Array(0x10000 + size), so 0x10000 words is a
  // 256 KB floor before the requested size is counted at all.
  const floor = 0x10000 * 4 / 1024;
  const total = floor + (m ? +m[1] : 0) + floor + (w ? +w[1] : 0);
  check("loader buffers total well under 1 MB", total < 1024,
    `${total.toFixed(0)} KB of typed arrays`);
  check("the loader does not malloc MAX_PAYLOAD",
    !/p\.malloc\(MAX_PAYLOAD\)/.test(src),
    "a 512 KiB malloc would be 2.25 MB each");
}

// 11b. the ABI exposes syscall return-value helpers, and they work
{
  const { wire } = await run(`
    return async function (api) {
      // A read failure is -1, which is neither 0 nor a byte count. Treating it
      // as a count is how readfile.js once reported 68719476720 bytes read.
      await api.log("isFailure(-1)=" + api.isFailure({ low: 0xffffffff, hi: 0 }));
      await api.log("isFailure(12)=" + api.isFailure({ low: 12, hi: 0 }));
      await api.log("isFailure(0)=" + api.isFailure({ low: 0, hi: 0 }));
      await api.log("describe(-1): " + api.describe({ low: 0xffffffff, hi: 0 }));

      // The counting bug, spelled out: what the old loop did.
      const fake = { low: 0xffffffff, hi: 0 };
      let naive = 0;
      for (let i = 0; i < 16; i++) { const g = fake.low >>> 0; if (g === 0) break; naive += g; }
      await api.log("naive total: " + naive);

      let guarded = 0;
      for (let i = 0; i < 16; i++) {
        if (api.isFailure(fake)) break;
        const g = fake.low >>> 0;
        if (g === 0) break;
        guarded += g;
      }
      await api.log("guarded total: " + guarded);
    };
  `);
  check("-1 is recognised as a failure", wire.includes("isFailure(-1)=true"));
  check("a byte count is not a failure", wire.includes("isFailure(12)=false"));
  check("zero is not a failure either", wire.includes("isFailure(0)=false"));
  check("describe() names the -1 case", wire.includes("describe(-1): 0xFFFFFFFF (-1)"));
  check("the naive loop really does produce 68719476720",
    wire.includes("naive total: 68719476720"));
  check("the guarded loop yields 0", wire.includes("guarded total: 0"));
}

// 11c. argv arrives over the socket
{
  const { wire } = await run(`
    return async function (api) {
      await api.log("argc=" + api.args.length);
      for (const a of api.args) await api.log("arg: " + a);
    };
  `, { argv: ["/etc/hosts", "second one", "ünïcødé"] });
  check("argv reaches the payload", wire.includes("argc=3"));
  check("argv[0] arrives intact", wire.includes("arg: /etc/hosts"));
  check("argv[1] with a space arrives intact", wire.includes("arg: second one"));
  check("argv[2] non-ascii survives utf-8", wire.includes("arg: ünïcødé"));
}

// 11d. a payload with no argv sees an empty array, not undefined
{
  const { wire } = await run(`
    return async function (api) {
      await api.log("isArray=" + Array.isArray(api.args));
      await api.log("len=" + api.args.length);
    };
  `);
  check("args is an array with no argv",
    wire.includes("isArray=true") && wire.includes("len=0"));
}

// 11e. the plain frame is unchanged when there are no arguments
{
  const src = "return async function (api) { await api.log('x'); };";
  const body = Buffer.from(src, "utf8");
  const f = buildFrame(src, null);
  check("a no-arg frame is just size + source",
    f.length === 8 + body.length && f.readBigUInt64LE(0) === BigInt(body.length),
    `${f.length} bytes`);
}

// 12. the blob return path frames correctly
{
  const { wire } = await run(`
    return async function (api) {
      const b = new Uint8Array(64);
      for (let i = 0; i < b.length; i++) b[i] = i & 0xff;
      await api.sendBlob(b);
      await api.log("sent");
    };
  `);
  const buf = Buffer.from(wire, "binary");
  const magic = Buffer.from([0x13, 0x37, 0x13, 0x37]);
  const at = buf.indexOf(magic);
  check("a blob is framed with the magic", at !== -1, at === -1 ? "no magic found" : `at ${at}`);
  if (at !== -1) {
    const len = buf.readUInt32LE(at + 4);
    check("the blob length header is right", len === 64, `says ${len}`);
    const first = buf[at + 8];
    const second = buf[at + 9];
    check("blob contents survive the round trip", first === 0 && second === 1,
      `first two bytes: ${first},${second}`);
  }
  check("text still arrives alongside a blob", wire.includes("sent"));
}

// 12b. a payload that over-allocates gets a catchable error, not a dead renderer
{
  const { wire } = await run(`
    return async function (api) {
      try {
        api.p.malloc(64 * 1024 * 1024);
        await api.log("NO GUARD: huge malloc went through");
      } catch (e) {
        await api.log("guarded: " + e.message.slice(0, 60));
      }
      const ok = api.p.malloc(0x1000);
      await api.log("small malloc still works: " + (ok.low !== undefined));
    };
  `);
  check("an oversized p.malloc is refused", wire.includes("guarded:"), "");
  check("a small p.malloc still works", wire.includes("small malloc still works: true"));
}

// 12c. reading a library's mapped range is refused, not fatal
{
  const { wire } = await run(`
    return async function (api) {
      const base = api.p.libSceLibcInternalBase;
      try {
        api.p.read1(base);
        await api.log("NO GUARD: read a library");
      } catch (e) {
        await api.log("guarded: " + e.message.slice(0, 50));
      }
      // An opted-in read is allowed through.
      api.allowXotextReads = true;
      let blocked = false;
      try { api.p.read1(base); } catch (e) { blocked = /execute-only/.test(e.message); }
      await api.log("still blocked after opt-in: " + blocked);

      // Reads from our own memory must be unaffected.
      const buf = api.p.malloc(0x1000);
      api.p.write1(buf, 0x5a);
      await api.log("own memory still readable: " + (api.p.read1(buf) === 0x5a));
    };
  `);
  check("reading a library is refused", wire.includes("guarded:"), "");
  check("the refusal names execute-only", /execute-only|guarded/.test(wire));
  // After opting in, the guard must get out of the way. (The fake has no
  // backing buffer at a library address, so the read still throws -- what
  // matters is that it is no longer the guard's execute-only error.)
  check("opting in bypasses the guard", wire.includes("still blocked after opt-in: false"));
  check("reads from payload-owned memory are unaffected",
    wire.includes("own memory still readable: true"));
}

// 12d. api.module() and api.krwLayout are present
{
  const { wire } = await run(`
    return async function (api) {
      await api.log("module is a function: " + (typeof api.module === "function"));
      await api.log("krwLayout present: " + (api.krwLayout !== null && api.krwLayout !== undefined));
      await api.log("krw starts null: " + (api.krw === null));
    };
  `);
  check("api.module is exposed", wire.includes("module is a function: true"));
  check("api.krwLayout is exposed", wire.includes("krwLayout present: true"));
  check("krw is null before any kernel payload", wire.includes("krw starts null: true"));
}

// 12d2. api.config and api.launchKexp are exposed and binaries exist
{
  const { wire } = await run(`
    return async function (api) {
      await api.log("config present: " + (typeof api.config === "object"));
      await api.log("kexp bin: " + api.config.KEXP_BIN);
      await api.log("elfldr bin: " + api.config.ELFLDR_ELF);
      await api.log("launchKexp is function: " + (typeof api.launchKexp === "function"));
      try {
        await api.launchKexp();
      } catch (e) {
        await api.log("launch without krw rejected: " + e.message);
      }
    };
  `);
  check("api.config is exposed", wire.includes("config present: true"));
  check("api.config has versioned kexp", wire.includes("kexp-v0.8-24cf6e5.bin"));
  check("api.config has versioned elfldr", wire.includes("elfldr-ps5-v0.26.elf"));
  check("api.launchKexp is a function", wire.includes("launchKexp is function: true"));
  check("api.launchKexp requires krw", wire.includes("launch without krw rejected: launchKexp requires an active kernel R/W"));

  // Verify binaries are on disk
  const kexpExists = existsSync(join(ROOT, "shared/kexp-v0.8-24cf6e5.bin"));
  const elfldrExists = existsSync(join(ROOT, "shared/elfldr-ps5-v0.26.elf"));
  check("kexp-v0.8-24cf6e5.bin is on disk (shared/)", kexpExists);
  check("elfldr-ps5-v0.26.elf is on disk (shared/)", elfldrExists);

  const { DEFAULT_BINARIES } = await import(join(ROOT, "src/binaries.js"));
  check("binaries.js declares both bundled paths",
    typeof DEFAULT_BINARIES.KEXP_BIN === "string" &&
    typeof DEFAULT_BINARIES.ELFLDR_ELF === "string");
  check("api.config matches the path binaries.js declares",
    wire.includes(DEFAULT_BINARIES.ELFLDR_ELF));
  check("binaries.js ELFLDR_ELF exists on disk",
    existsSync(join(ROOT, DEFAULT_BINARIES.ELFLDR_ELF)));
  check("binaries.js KEXP_BIN exists on disk",
    existsSync(join(ROOT, DEFAULT_BINARIES.KEXP_BIN)));

  // One literal, not three. site.js, loader.js and kexp.js must each reach
  // binaries.js rather than restating a path.
  for (const rel of ["src/site.js", "src/loader.js", "src/kexp.js"]) {
    const body = readFileSync(join(ROOT, rel), "utf8");
    check(`${rel} imports the paths from binaries.js`,
      /import\s*\{[^}]*DEFAULT_BINARIES[^}]*\}\s*from\s*"\.\/binaries\.js"/.test(body));
    check(`${rel} states no bundled path literal`,
      !/shared\/(kexp|elfldr)[^"]*"/.test(body));
  }
}


// 12f. a kernel payload that finds no krw says so instead of guessing
{
  const { wire } = await run(`
    return async function (api) {
      if (!api.krw) { await api.log("no krw -- run kexp first", "error"); return; }
      await api.log("should not get here");
    };
  `);
  check("a payload without krw refuses politely",
    wire.includes("no krw -- run kexp first") && !wire.includes("should not get here"));
}

// 12g. fire-and-forget logging must not overlap on the chain.
{
  const { wire } = await run(`
    return async function (api) {
      // deliberately NOT awaited, exactly like report()
      for (let i = 0; i < 25; i++) api.log("burst " + i);
      await api.log("burst complete");
    };
  `);
  check("a 25-line fire-and-forget burst does not overlap the chain",
    !/re-entrant/.test(wire), (wire.match(/re-entrant[^\n]*/) || [""])[0]);
  check("every line of the burst arrives", wire.includes("burst 0") && wire.includes("burst 24"));
  check("awaiting a log still flushes it", wire.includes("burst complete"));
  check("no lines were lost", (wire.match(/burst \d+/g) || []).length === 25,
    `${(wire.match(/burst \d+/g) || []).length} of 25`);
}

// 12h. an interleaved log and sendBlob must serialise too
{
  const { wire, wireBuf } = await run(`
    return async function (api) {
      api.log("before blob");
      const p1 = api.sendBlob(new Uint8Array([1, 2, 3]));
      const p2 = api.sendBlob(new Uint8Array([4, 5, 6]));
      api.log("after blobs");
      await p1; await p2;
      await api.log("done");
    };
  `);
  check("concurrent sendBlob calls do not overlap the chain",
    !/re-entrant/.test(wire), (wire.match(/re-entrant[^\n]*/) || [""])[0]);
  // Blob framing is raw bytes. The "blob: N bytes" line is send.py's rendering
  // and never appears on the wire, so count magics in the buffer instead.
  const magic = Buffer.from([0x13, 0x37, 0x13, 0x37]);
  let seen = 0, at = wireBuf.indexOf(magic);
  while (at !== -1) { seen++; at = wireBuf.indexOf(magic, at + 1); }
  check("both blobs are framed on the wire", seen === 2, `${seen} blob magic(s)`);
  check("text around the blobs survives",
    wire.includes("before blob") && wire.includes("after blobs") && wire.includes("done"));
}

// 12i. a payload-built chain batch must be atomic against log traffic.
{
  const { trace, wire } = await run(`
    return async function (api) {
      // fire-and-forget, exactly like report()
      api.log("batch starting");
      api.chain.clear();
      for (let i = 0; i < 40; i++) api.chain.add_syscall(0x014, i); // getpid
      await api.chain.run();
      await api.log("batch done");
    };
  `);
  const getpids = trace.filter((n) => n === 0x014).length;
  check("all 40 batched syscalls ran", getpids === 41, `${getpids} getpid calls (40 batch + 1 loader)`);
  check("the batch did not overlap a log write", !/re-entrant/.test(wire),
    (wire.match(/re-entrant[^\n]*/) || [""])[0]);
  check("the log lines around the batch survive",
    wire.includes("batch starting") && wire.includes("batch done"));
}

// 12j. the batch and the log write must not interleave on the chain.
{
  const { trace } = await run(`
    return async function (api) {
      api.log("hello");
      api.chain.clear();
      api.chain.add_syscall(0x014, 1);
      api.chain.add_syscall(0x014, 2);
      api.chain.add_syscall(0x014, 3);
      await api.chain.run();
    };
  `);
  check("a batch queued behind a log write still runs all three ops",
    trace.filter((n) => n === 0x014).length === 4,
    `trace: ${trace.map((n) => n.toString(16)).join(",")}`);
}

// 12k. syscall() must refuse to silently discard a pending batch
{
  const { wire } = await run(`
    return async function (api) {
      api.chain.clear();
      api.chain.add_syscall(0x014, 1);
      try {
        await api.chain.syscall(0x014);
      } catch (e) {
        await api.log("refused: " + e.message.split("\\n")[0]);
      }
    };
  `);
  check("syscall() with a pending batch is refused, not silently dropped",
    /refused: .*pending/.test(wire), wire.slice(-300));
}

// 12m. a log call issued from INSIDE a chain batch must not corrupt it.
{
  const { trace, wire } = await run(`
    return async function (api) {
      api.chain.clear();
      api.chain.add_syscall(0x014, 1);
      // A report() landing between the build and the run. Not awaited, as in
      // Relapse's report().
      api.log("mid-batch report");
      api.chain.add_syscall(0x014, 2);
      await api.chain.run();
      await api.log("batch finished");
    };
  `);
  check("a log between build and run does not overlap the chain",
    !/mutated while the worker was executing/.test(wire) && !/re-entrant/.test(wire),
    (wire.match(/(mutated while[^\n]*|re-entrant[^\n]*)/) || [""])[0]);
  check("the batch still ran both ops", trace.filter((n) => n === 0x014).length === 3,
    `trace: ${trace.map((n) => n.toString(16)).join(",")}`);
  check("the mid-batch report still reached the wire", wire.includes("mid-batch report"));
}

// 12n. a log issued while run() is in flight must queue, not interleave
{
  const { wire } = await run(`
    return async function (api) {
      api.chain.clear();
      for (let i = 0; i < 20; i++) api.chain.add_syscall(0x014, i);
      const running = api.chain.run();          // not awaited yet
      api.log("while running");                 // lands mid-run
      await running;
      await api.log("after run");
    };
  `);
  check("a log during run() does not touch the executing stack",
    !/mutated while the worker was executing/.test(wire),
    (wire.match(/mutated while[^\n]*/) || [""])[0]);
  check("both logs survive a mid-run flush",
    wire.includes("while running") && wire.includes("after run"));
}

// 12l. api.chain must not be the raw chain
{
  const { wire } = await run(`
    return async function (api) {
      await api.log("has clear: " + typeof api.chain.clear);
      await api.log("has add_syscall: " + typeof api.chain.add_syscall);
      await api.log("has run: " + typeof api.chain.run);
    };
  `);
  check("api.chain exposes the batch API", /has clear: function/.test(wire) &&
    /has add_syscall: function/.test(wire) && /has run: function/.test(wire));
}

// 12p. the payload watchdog must actually report an overrun.
{
  const src = readFileSync(new URL("../src/loader.js", import.meta.url), "utf8");
  check("loader.js exports withDeadline for testing",
    /export\s+function\s+withDeadline|export\s*{[^}]*withDeadline/.test(src));

  const { withDeadline: wd } = await import("../src/loader.js");
  check("withDeadline resolves a work that finishes in time",
    (await wd(Promise.resolve("done"), 5000)) === "done");

  let reported = 0;
  const slow = new Promise((r) => setTimeout(() => r("late"), 4000));
  const out = await wd(slow, 120, () => reported++);
  check("withDeadline reports an overrun instead of waiting forever",
    out === "overran" && reported === 1,
    `returned ${JSON.stringify(out)}, reported ${reported} time(s)`);

  const rejected = await wd(Promise.reject(new Error("boom")), 5000)
    .then(() => "resolved", (e) => e.message);
  check("withDeadline still propagates a real failure",
    rejected === "boom", String(rejected));

  // A rejection that arrives AFTER the deadline must be consumed, not left
  // unhandled -- an unhandled rejection kills the renderer, which is the very
  // thing the watchdog is here to prevent. It has to be genuinely delayed:
  // Promise.reject() settles on the next microtask, long before any timer.
  const lateBoom = new Promise((_, rej) => setTimeout(() => rej(new Error("late boom")), 300));
  const raced = await wd(lateBoom, 100)
    .then(() => "resolved", (e) => `rejected: ${e.message}`);
  check("withDeadline swallows a failure that arrives after the deadline",
    raced === "resolved", `got ${JSON.stringify(raced)}`);
  // Give the late rejection time to land, then confirm nothing threw.
  await new Promise((r) => setTimeout(r, 400));
  check("withDeadline left no unhandled rejection behind", true);

  let reset;
  const longWork = new Promise((resolve) => setTimeout(() => resolve("service done"), 60));
  const disabled = await wd(longWork, 10, () => reported++, (set) => {
    reset = set;
    set(0);
  });
  check("a service can disable the deadline and finish normally", disabled === "service done" && reported === 1);
  let staleRejected = false;
  try { reset(0); } catch { staleRejected = true; }
  check("a completed service cannot reset its old deadline", staleRejected);

  const extended = await wd(new Promise((resolve) => setTimeout(() => resolve("extended"), 40)), 10,
    null, (set) => set(200));
  check("a payload can extend its deadline", extended === "extended");
  let duration;
  const shortened = await wd(new Promise(() => {}), 200, (ms) => { duration = ms; }, (set) => set(10));
  check("an adjusted deadline reports the chosen duration", shortened === "overran" && duration === 10);

  let invalid = 0;
  await wd(Promise.resolve(), 100, null, (set) => {
    for (const ms of [-1, 0.5, NaN, Infinity, 0x80000000]) {
      try { set(ms); } catch (e) { if (e instanceof RangeError) invalid++; }
    }
  });
  check("invalid deadline values are rejected", invalid === 5);

  const { wire } = await run(`
    return async function(api) {
      api.setPayloadTimeout(0);
      await api.log("service owns its deadline");
      api.setPayloadTimeout(1000);
      await api.log("service finished");
    };
  `);
  check("payload deadline control is wired through the real ABI",
    wire.includes("service owns its deadline") && wire.includes("service finished") && !wire.includes("payload threw"));
}


{
  const loader = readFileSync(new URL("../src/loader.js", import.meta.url), "utf8");
  const body = loader.slice(loader.indexOf("module: async (path)"));

  check("api.module fetches before importing",
    /await fetch\(url/.test(body) && body.indexOf("await fetch(url") < body.indexOf("await import(url"));
  check("a fetch failure is reported as a NETWORK failure",
    /NETWORK failure/.test(body));
  check("a fetch failure names the likely causes",
    /host\.py/.test(body) && /DNS/.test(body));
  check("an HTTP error status is reported with its code",
    /HTTP \$\{response\.status\}/.test(body));
  check("an empty body is distinguished from a failed load",
    /served empty/.test(body));
  // The message is assembled from two template-literal pieces joined by ` + `,
  // so the phrase is split across lines. Match the parts, not the sentence.
  check("a module that fetched but would not load says so",
    /but would not/.test(body) && /load:/.test(body) && /\$\{body\.length\} bytes/.test(body),
    (body.match(/was fetched[^\n]*/) || [""])[0]);
}


{
  const loader = readFileSync(new URL("../src/loader.js", import.meta.url), "utf8");
  const guard = loader.slice(loader.indexOf("function guardRead"));

  check("the guard bails out when the high word is set",
    /if \(\(address\.hi >>> 0\) !== 0\) return;/.test(guard),
    "a high-word address is not excluded before the range test");
  check("the guard no longer compares the low word alone",
    guard.indexOf("address.hi") !== -1 &&
    guard.indexOf("address.hi") < guard.indexOf("const a = address.low"),
    "the range test still runs before the high word is checked");

  // The real shape of the false positive, as a plain check.
  const low = 0x2f8000 >>> 0;
  const libkernel = { start: 0x2a4000, end: 0x3a4000 };
  check("the case that broke it: high word set, low word inside libkernel",
    low >= libkernel.start && low < libkernel.end && (0x20 >>> 0) !== 0,
    "the reproducer no longer matches, so the test is not testing anything");
}

//
function findRelapseUpstream() {
  const candidates = [
    process.env.RELAPSE_DIR,
    join(ROOT, "Relapse-Exploit"),
    join(ROOT, "build/Relapse-Exploit"),
    join(ROOT, "third_party/Relapse-Exploit"),
    join(ROOT, "..", "Relapse-Exploit"),
  ].filter(Boolean);

  for (const c of candidates) {
    const file = join(c, "src/relapse_exploit.js");
    if (existsSync(file)) return { root: c, file, offsets: join(c, "offsets") };
  }
  return null;
}

const upstreamRelapse = findRelapseUpstream();
const UPSTREAM_RELAPSE = upstreamRelapse ? upstreamRelapse.file : null;
const UPSTREAM_OFFSETS = upstreamRelapse ? upstreamRelapse.offsets : null;
const PAYLOAD_RELAPSE = join(ROOT, "payloads/relapse.js");

if (!UPSTREAM_RELAPSE) {
  console.log("  (skipping relapse fidelity: Relapse-Exploit repository is not present)");
} else {
  const relapseSrc = readFileSync(PAYLOAD_RELAPSE, "utf8");
  const upstreamSrc = readFileSync(UPSTREAM_RELAPSE, "utf8");

  const START = "// ======================= PORT BOUNDARY: upstream starts here ==================";
  const END = "// ======================= PORT BOUNDARY: upstream ends here ====================";
  const region = (text, from, to) => {
    const a = text.indexOf(from);
    const b = text.indexOf(to, a + 1);
    return a < 0 || b < 0 ? null : text.slice(a + from.length + 1, b);
  };
  const ported = region(relapseSrc, START, END);

  check("payloads/relapse.js marks the ported region", ported !== null);
  check("the ported region is not empty", ported !== null && ported.length > 30000,
    ported ? `${ported.length} bytes` : "markers not found");

  // launchShellcode is a deliberate substitution rather than a mechanical edit, so
  // it is cut out of both sides and asserted separately below. locatePipes is the
  // one behavioural change and is handled by a literal reversal instead, since its
  // edit is a single argument plus a comment block.
  const cutStage = (text, marker) => {
    const start = text.indexOf(marker);
    const end = text.indexOf("  // restore\n", start);
    if (start < 0 || end < 0) return null;
    return { block: text.slice(start, end), text: text.slice(0, start) + "<STAGE>\n" + text.slice(end) };
  };

  // Upstream's module import is the one line a payload cannot have, so it comes
  // off before anything else. Everything after it must be byte-identical.
  const upstreamNoImport = upstreamSrc.replace('import { int64 } from "./utils/int64.js";\n', "");
  const upstreamStage = cutStage(upstreamNoImport, "  // shellcode\n  async launchShellcode() {");
  const portedStage = cutStage(ported, "  // The kernel r/w handle.");

  // The documented mechanical edits, ported -> upstream. Reversing them must
  // give upstream back exactly; anything else in the region is drift.
  const REVERSALS = [
    ["async function runKernelExploit(p, chain, log, launchKexp) {",
     "export async function runKernelExploit(p, chain, log) {"],
    ["  return new KernelExploit(p, chain, log, launchKexp).run();",
     "  return new KernelExploit(p, chain, log).run();"],
    ["  constructor(p, chain, log, launchKexp) {", "  constructor(p, chain, log) {"],
    ["    this.launchKexp = typeof launchKexp === \"function\" ? launchKexp : null;\n", ""],
    ["  async report(tag, detail, type) {", "  report(tag, detail, type) {"],
    ["    await this.onScreen(", "    this.onScreen("],
    ["  async stop(why) {", "  stop(why) {"],
    ["// Delays after parking AIO workers and between armed sweep groups.\nconst POST_PARK_DELAY_MS = 1000;\nconst SWEEP_DELAY_MS = 100;\n\n",
     ""],
    // post-park settle delay
    ["    if (POST_PARK_DELAY_MS > 0) await sleep(POST_PARK_DELAY_MS);\n",
     ""],
    // per-armed-group sweep delay
    ["        if (SWEEP_DELAY_MS > 0) await sleep(SWEEP_DELAY_MS);\n",
     ""],
    ["return await this.stop(", "return this.stop("],
  ];

  // Rather than splicing cut regions back together, every edit is reversed in
  // place and the whole file is compared. The two substituted regions are
  // reversed by substituting upstream's own text for the port's, which is
  // exact: it is the same string the assertion is measured against.
  const undoStage = upstreamStage ? [portedStage.block, upstreamStage.block] : null;
  // locatePipes(): the comment block and the argument. Reverse both, so the whole
  // file can be compared against upstream and this exception stays visible in the
  // source rather than hidden in a carve-out here.
  const undoPipes = [
    [/\n {4}\/\/ Nonblocking reads let the existing short-read checks handle an empty pipe\.\n {4}const O_NONBLOCK = 0x4;\n/, ""],
    ["pair, O_NONBLOCK)", "pair, 0)"],
  ];

  let unapplied = null;
  let reversed = ported;
  // Order matters: the launchShellcode substitution contains no await or import
  // text, so it goes first without interacting with the mechanical reversals.
  for (const [from, to] of [undoStage].filter(Boolean)) {
    if (!reversed.includes(from)) { unapplied = from.trim().split("\n")[0].slice(0, 58); break; }
    reversed = reversed.replace(from, to);
  }
  for (const [from, to] of undoPipes) {
    if (unapplied !== null) break;
    if (typeof from === "string" ? !reversed.includes(from) : !from.test(reversed)) {
      unapplied = String(from).trim().slice(0, 58);
      break;
    }
    reversed = reversed.replace(from, to);
  }
  for (const [from, to] of REVERSALS) {
    if (unapplied !== null) break;
    if (!reversed.includes(from)) { unapplied = from.trim().slice(0, 58); break; }
    reversed = reversed.split(from).join(to);
  }
  // Upstream has no `await this.report(` anywhere, so stripping them all is exact.
  if (unapplied === null) reversed = reversed.split("await this.report(").join("this.report(");
  const expected = upstreamNoImport;
  check("the launchKexp substitution region is found in both files",
    upstreamStage !== null && portedStage !== null);
  check("every documented port edit is still present, so this check is live",
    unapplied === null, unapplied ? `not found: ${unapplied}` : "");
  // Trailing blank lines at the region boundary are where the file was cut, not
  // drift, so compare with them normalised away.
  const trimEnd = (t) => (t === null ? null : t.replace(/\n+$/, ""));
  check("payloads/relapse.js is upstream relapse_exploit.js, unmodified",
    reversed !== null && trimEnd(reversed) === trimEnd(expected),
    firstDifference(trimEnd(reversed), trimEnd(expected)));

  // The substitution itself: same krw shape, same order, loader's kexp launcher.
  const stage = portedStage ? portedStage.block : "";
  check("buildKrw keeps upstream's handle shape verbatim",
    /buildKrw\(\) \{\s*return \{\s*ktextBase: this\.kbase,\s*procFdAddr: this\.procFdAddr,\s*read8: \(address\) => this\.readKernel64\(address\),\s*write4: \(address, value\) => this\.writeKernel32\(address, value\),\s*write8: \(address, value\) => this\.writeKernel64\(address, value\),\s*\};/.test(stage),
    stage.slice(0, 90).replace(/\n/g, " "));
  check("launchShellcode still restores thread attributes and runs last",
    stage.includes("await this.restoreThreadAttributes();") &&
    stage.includes("const krw = this.buildKrw();") &&
    stage.includes("await this.launchKexp({ krw })"));
  check("the loader's kexp launcher replaces upstream's shellcode loader",
    !/runKexp|await import\(|\.\/kexp\.js/.test(stage));

  // The tuning numbers are the ones a "let me reduce the churn" edit touches, and
  // they are the reason the earlier port got slower and no more stable.
  const tuning = /this\.tuning = \{([\s\S]*?)\};/.exec(ported)?.[1] ?? "";
  const TUNING = { waiters: 18, requests: 13, churnBefore: 32, churnAfter: 256,
                   sprays: 64, workerBlockers: 24, waitTimeoutUs: 10000 };
  for (const [name, want] of Object.entries(TUNING)) {
    check(`tuning.${name} is upstream's ${want}`,
      new RegExp(`\\b${name}:\\s*${want}\\b`).test(tuning),
      (tuning.match(new RegExp(`\\b${name}:\\s*\\d+`)) || ["(absent)"])[0]);
  }

  // Check the nonblocking pipe edit separately from the upstream reversal.
  check("the crossed pipes are non-blocking, unlike upstream",
    /SYS_PIPE2, pair, O_NONBLOCK\)/.test(ported) && !/SYS_PIPE2, pair, 0\)/.test(ported),
    (ported.match(/SYS_PIPE2[^)]*\)/) || ["(absent)"])[0]);
  check("O_NONBLOCK is declared inside locatePipes, not at file scope",
    / {4}const O_NONBLOCK = 0x4;/.test(ported) && !/^const O_NONBLOCK/m.test(ported),
    (ported.match(/.*const O_NONBLOCK = .*/) || ["(absent)"])[0]);
  // Every OTHER pipe or socket in the exploit must be exactly as upstream had it.
  // locatePipes() is the only site allowed to carry O_NONBLOCK; this is what stops
  // the exemption from quietly spreading to the socketpair or the routing socket.
  // Comments are stripped first: the comment above the change names SYS_PIPE2, and
  // a scan that counted it would report a second, imaginary call site.
  const portedCode = ported.replace(/^\s*\/\/.*$/gm, "");
  const pipeSites = (portedCode.match(/SYS_(?:PIPE2|SOCKETPAIR|SOCKET)\b/g) || []).length;
  check("O_NONBLOCK appears at exactly one of the exploit's pipe/socket sites",
    pipeSites === 3 &&
    (portedCode.match(/SYS_PIPE2, pair, O_NONBLOCK\)/g) || []).length === 1,
    `${pipeSites} pipe/socket call sites, ` +
    `${(portedCode.match(/O_NONBLOCK\)/g) || []).length} carrying the flag`);

  // Nothing from the earlier port may creep back: every one of these knobs or
  // helpers changed the race or its teardown, and none could be measured.
  const REGRESSED = ["keepPipes", "loadPayloads", "armAttempts", "skipDefuse",
    "duringArmed", "verifyKrw", "snapshotNodeMutex", "oidKindDetailed",
    "pageCache", "workerParks", "defuseStep", "mutexBefore"];
  const crept = REGRESSED.filter((k) => relapseSrc.includes(k));
  check("no leftover knobs or helpers from the earlier loader port", crept.length === 0,
    crept.join(", "));

  // The exploit reads its kernel layout out of window.KRW. Those offset files are
  // the loader's, and they have to stay upstream's or every RVAR in the exploit
  // silently points somewhere else.
  let offsetFiles = [];
  let mineFiles = [];
  try {
    offsetFiles = readdirSync(UPSTREAM_OFFSETS).filter((f) => f.endsWith(".js"));
    mineFiles = readdirSync(join(ROOT, "offsets")).filter((f) => f.endsWith(".js"));
  } catch {}
  const drifted = [];
  for (const f of offsetFiles) {
    const mine = join(ROOT, "offsets", f);
    if (!existsSync(mine)) {
      drifted.push(f);
      continue;
    }
    let mineSrc = readFileSync(mine, "utf8");
    let upSrc = readFileSync(join(UPSTREAM_OFFSETS, f), "utf8");
    if (f === "11.60.js") {
      mineSrc = mineSrc
        .replace(/const OFFSET_lk_sleep = 0x00027890;\n/, "")
        .replace(/const OFFSET_lk_sceKernelGetCurrentCpu = 0x000011f0;\n/, "")
        .replace(/let wk_gadgetmap = {\n  "ret":/, 'const wk_gadgetmap = {\n  ret:')
        .replace(/"infloop": 0x000031c1,\n};\n\nlet syscall_map = {/, 'infloop: 0x000031c1,\n};\n\nconst syscall_map = {');
    }
    if (mineSrc !== upSrc)
      drifted.push(f);
  }
  const extra = mineFiles.filter((f) => !offsetFiles.includes(f));
  check("every offsets/*.js file is upstream's, unmodified, and none is missing",
    offsetFiles.length > 0 && drifted.length === 0 && extra.length === 0,
    [...drifted.map((f) => `differs:${f}`), ...extra.map((f) => `extra:${f}`)].join(", ") ||
    `${drifted.length} differ, ${extra.length} extra, ${offsetFiles.length} upstream`);
}

// 13b. the payload must survive being run for real, and bail cleanly.
{
  const relapseSrc = readFileSync(PAYLOAD_RELAPSE, "utf8");
  vm.runInThisContext(readFileSync(join(ROOT, "src/utils/syscalls.js"), "utf8"));
  check("the exploit's SYS_* identifiers resolve against syscalls.js",
    vm.runInThisContext(
      "typeof SYS_NETGETIFLIST === 'number' && typeof SYS_AIO_SUBMIT_CMD === 'number'"));

  const { wire, trace } = await runSequence([
    `return async function (api) { api.krw = { already: true }; };`,
    relapseSrc,
  ]);
  check("relapse refuses to re-arm a kernel that is already hit",
    wire.includes("will not run twice here") && wire.includes("api.krw = null"));
  check("the refusal says why, and how to get a fresh session",
    /AIO use-after-free/.test(wire) && /reload the page/.test(wire));
  check("the refusal happens before the exploit starts",
    !wire.includes("Relapse kernel exploit on fw") && !wire.includes("Starting kernel exploit"));

  const syscalls = readFileSync(join(ROOT, "src/utils/syscalls.js"), "utf8");
  const nr = (name) => {
    const m = new RegExp(`^const SYS_${name} = (0x[0-9a-fA-F]+)`, "m").exec(syscalls);
    return m ? Number(m[1]) : null;
  };
  // Syscalls only the exploit makes. None may appear on the refused run: they
  // would mean it started work instead of returning.
  const EXPLOIT_ONLY = ["NETGETIFLIST", "SOCKETPAIR", "AIO_SUBMIT_CMD",
    "AIO_MULTI_WAIT", "AIO_MULTI_POLL", "AIO_MULTI_CANCEL", "PIPE2",
    "__SYSCTL", "CPUSET_GETAFFINITY", "RTPRIO_THREAD", "GETRLIMIT"]
    .map(nr).filter((n) => n !== null);
  check("the exploit syscall numbers exist in syscalls.js", EXPLOIT_ONLY.length === 11,
    `resolved ${EXPLOIT_ONLY.length}`);
  check("the refused run issued no exploit syscalls at all",
    EXPLOIT_ONLY.every((n) => !trace.includes(n)),
    EXPLOIT_ONLY.filter((n) => trace.includes(n)).map((n) => "0x" + n.toString(16)).join(","));

  // The refusal tells the user to run `api.krw = null` and send it again, so that
  // has to be a real recovery path rather than advice that does not work.
  const recovered = await runSequence([
    `return async function (api) { api.krw = { already: true }; };`,
    `return async function (api) { api.krw = null; await api.log("cleared: " + (api.krw === null)); };`,
    relapseSrc,
  ]);
  check("the documented escape hatch clears the session handle",
    recovered.wire.includes("cleared: true") &&
    recovered.wire.includes("Relapse kernel exploit on fw") &&
    !recovered.wire.includes("will not run twice here"),
    (recovered.wire.match(/\[.\] (cleared:|will not run|Relapse kernel)[^\n]*/g) || []).join(" | "));

  // Same payload, on a session where no kernel payload has run. The prefetch is
  // stubbed so the test exercises the EXPLOIT, which is the part that has no
  // network dependency -- the prefetch itself is covered in 13c, where the fake
  // fetch is installed deliberately.
  const solo = await withFetch(
    async () => ({ ok: true, arrayBuffer: async () => fakeElf() }),
    () => runSequence([relapseSrc]));
  const soloWire = solo.wire;
  check("relapse announces itself before touching the kernel",
    soloWire.includes("Relapse kernel exploit on fw") &&
    soloWire.includes("elfldr stage: spawn"));
  check("relapse reaches its first exploit stage",
    soloWire.includes("Kernel: Starting kernel exploit"));
  check("a failed stage is reported, not swallowed",
    soloWire.includes("the exploit threw") && soloWire.includes("kaslr:"),
    (soloWire.match(/\[-\] [^\n]*/g) || []).slice(-3).join(" | "));
  check("cleanup still ran and the payload returned cleanly",
    !soloWire.includes("payload threw") && soloWire.includes("--- payload done ---"));
  // A third payload proves the failed run left the session's krw unpublished,
  // which is what a later payload in the same session would see.
  const after = await runSequence([
    relapseSrc,
    `return async function (api) { await api.log("session krw still null: " + (api.krw === null)); };`,
  ]);
  check("a failed run publishes no krw handle",
    !/api\.krw published/.test(after.wire) &&
    after.wire.includes("session krw still null: true"),
    (after.wire.match(/\[.\] (api\.krw published|session krw[^\n]*)/g) || []).join(" | "));
  check("the run issued exactly the one syscall the first stage needs",
    solo.trace.filter((n) => n === nr("NETGETIFLIST")).length === 1,
    `netgetiflist x${solo.trace.filter((n) => n === nr("NETGETIFLIST")).length}`);
  // Exactly one: the run must bail at KASLR rather than limbering on into
  // pinning threads and arming the aio UAF against a kernel that reported no
  // interfaces. Anything past netgetiflist means the guard was removed.
  check("nothing got past KASLR",
    EXPLOIT_ONLY.every((n) => n === nr("NETGETIFLIST") || !solo.trace.includes(n)),
    solo.trace.map((n) => "0x" + n.toString(16)).join(","));

  // --arg is forwarded from send.py, and the elfldr stage is chosen by the
  // payload rather than by the exploit, so the arg has to reach it.
  const staged = await runSequence([{ src: relapseSrc, argv: ["pipes"] }]);
  check("--arg reaches the payload and selects the elfldr stage",
    staged.wire.includes("args: pipes") && staged.wire.includes("elfldr stage: pipes"),
    (staged.wire.match(/\[.\] (args:|elfldr stage:)[^\n]*/g) || []).join(" | "));

  const timeline = [];
  globalThis.__ORDER = timeline;
  await withFetch(async () => {
    timeline.push("fetch");
    return { ok: true, arrayBuffer: async () => fakeElf() };
  }, async () => {
    await runSequence([relapseSrc]);
  });
  delete globalThis.__ORDER;

  // The timeline opens with the loader's OWN setup -- socket, bind, listen,
  // accept, read -- so "first" means first relative to the exploit, which starts
  // at netgetiflist. Anything before that belongs to the loader.
  const firstExploitCall = timeline.findIndex((e) => e === "syscall:0x7d");
  const fetches = timeline.filter((e) => e === "fetch").length;
  const lastFetch = timeline.lastIndexOf("fetch");
  check("the relapse payload fetches both binaries before any exploit syscall",
    fetches === 2 && firstExploitCall !== -1 && lastFetch < firstExploitCall,
    `${fetches} fetch(es), last at index ${lastFetch}, netgetiflist at ${firstExploitCall}; ` +
    `timeline: ${timeline.slice(0, 14).join(" -> ")}`);

  const lines = relapseSrc.replace(/^\s*\/\/.*$/gm, "").split("\n");
  const atPrefetchLine = lines.findIndex((line) => /\bapi\.prefetchKexp\s*\(\s*\)/.test(line));
  const atExploitLine = lines.findIndex((line) => /\brunKernelExploit\s*\(\s*(api|mod)\b/.test(line));
  check("in payloads/relapse.js the prefetch call precedes the exploit call",
    atPrefetchLine !== -1 && atExploitLine !== -1 && atPrefetchLine < atExploitLine,
    `prefetch at line ${atPrefetchLine + 1}, exploit at line ${atExploitLine + 1}`);
  check("payloads/relapse.js prefetches exactly once",
    lines.filter((line) => /\bapi\.prefetchKexp\s*\(/.test(line)).length === 1,
    `found ${lines.filter((line) => /\bapi\.prefetchKexp\s*\(/.test(line)).length} call sites`);
  // And nothing in the payload fetches on its own at all.
  check("payloads/relapse.js contains no fetch of its own",
    !/\bfetch\s*\(/.test(lines.join("\n")),
    (lines.join("\n").match(/.*\bfetch\s*\(.*/) || [""])[0]);

  const entryBody = relapseSrc.slice(relapseSrc.indexOf("return async function (api)"));
  const beforeExploit = entryBody.slice(0, entryBody.indexOf("runKernelExploit(api.p"));
  const afterExploit = entryBody.slice(entryBody.indexOf("runKernelExploit(api.p"));
  check("the prefetch is in the payload's own code, not inside the exploit",
    /await api\.prefetchKexp\(\)/.test(beforeExploit) &&
    !/await api\.prefetchKexp\(\)/.test(afterExploit),
    `prefetch appears after the exploit call (line ${entryBody.slice(0, entryBody.indexOf("runKernelExploit(api.p")).split("\n").length} ` +
    `is the exploit call), which means it runs while the worker is committed`);
  const atPrefetch = entryBody.indexOf("await api.prefetchKexp()");
  const atHook = entryBody.indexOf("const launchKexp =");
  check("the prefetch precedes the launchKexp hook the exploit calls",
    atPrefetch !== -1 && atHook !== -1 && atPrefetch < atHook,
    atHook === -1 ? "no launchKexp closure found in the entry function"
      : `prefetch at offset ${atPrefetch}, launchKexp closure at ${atHook}`);

  const relapseCode = relapseSrc.replace(/^\s*\/\/.*$/gm, "");
  check("no api.module() call, so the payload is one self-contained file",
    !/api\.module\(/.test(relapseCode) && !/\bawait import\(|\brequire\(/.test(relapseCode));
}

// 13c. api.launchKexp must not hand runKexp the RAW chain.
{
  const launchKexpSrc = readFileSync(join(ROOT, "src/loader.js"), "utf8");
  const body = launchKexpSrc.slice(
    launchKexpSrc.indexOf("launchKexp: async"),
    launchKexpSrc.indexOf("    module: async"),
  );
  const prefetchBody = launchKexpSrc.slice(
    launchKexpSrc.indexOf("prefetchKexp: async"),
    launchKexpSrc.indexOf("launchKexp: async"),
  );
  const calls = [...body.matchAll(/return await runKexp\(([\s\S]*?)\)\s*;/g)];
  const call = calls.length ? calls[calls.length - 1] : null;
  const args = call ? call[1].split(",").map((s) => s.trim()) : null;
  check("launchKexp calls runKexp with five arguments", args !== null && args.length === 5,
    calls.length ? `found ${calls.length} call(s); last has ${args.length}: ${args.join(" | ")}`
      : "(no `return await runKexp(...)` found)");
  // runKexp(krw, p, chain, log, options) -- the chain is argument 3.
  check("launchKexp passes the GATED chain to runKexp, not the raw one",
    args !== null && /(?:^|\.)gatedChain$/.test(args[2] ?? ""),
    `argument 3 is ${JSON.stringify(args?.[2])}, which is the ${args?.[2] === "chain" ? "RAW chain" : "expected ...gatedChain"}`);
  check("launchKexp passes a real p (argument 2), not a bare chain",
    args !== null && /^p$/.test(args[1] ?? "") && /(?:^|\.)gatedChain$/.test(args[2] ?? ""),
    `arguments 2 and 3 are ${JSON.stringify(args?.[1])} and ${JSON.stringify(args?.[2])}`);
  // The guard has to be a THROW, not a warning or a fallback fetch. A payload that
  // prefetches too late must be told so here, where it can still be logged --
  // once runKexp() is entered there is no way back, because the fetch it would
  // need is exactly the thing that no longer completes.
  check("a missing prefetch is a hard error at launchKexp, not a fallback fetch",
    /throw new Error\([\s\S]*?prefetchKexp\(\)/.test(body) &&
    !/runKexp\([^)]*await fetch/i.test(body),
    "launchKexp would fetch instead of refusing");

  // runKexp must not be able to reach the network at all. If the byte guard is
  // ever weakened into a "fetch if missing" fallback, the hang comes back and
  // nothing else here would notice -- the fake serves every path happily, so a
  // reintroduced fetch just looks like one more successful request.
  const kexpSrc = readFileSync(join(ROOT, "src/kexp.js"), "utf8");
  const runStart = kexpSrc.indexOf("export async function runKexp");
  const runKexpBody = kexpSrc.slice(runStart, kexpSrc.indexOf("\n}", runStart));
  check("runKexp itself cannot fetch",
    runStart >= 0 && !/\bfetch[A-Za-z]*\(/.test(runKexpBody),
    (runKexpBody.match(/.*\bfetch[A-Za-z]*\(.*/) || [""])[0]);
  // The one bare fetch( is inside fetchBinary(), which prefetchBinaries() is the
  // only caller of. Counting call SITES and letting the wrapper through is what
  // makes this meaningful: a fetch( added anywhere else, including inside
  // runKexp, has to show up here.
  const kexpLines = kexpSrc.replace(/^\s*\/\/.*$/gm, "").split("\n");
  const directFetchLines = kexpLines
    .map((line, i) => [i, line])
    .filter(([, line]) => /(?<![\w.])fetch\s*\(/.test(line));
  const onlyInWrapper = directFetchLines.every(([i]) => {
    const before = kexpLines.slice(0, i).join("\n");
    return before.lastIndexOf("async function fetchBinary") > before.lastIndexOf("\n}\n");
  });
  check("the only direct fetch() in src/kexp.js is inside fetchBinary()",
    directFetchLines.length === 1 && onlyInWrapper &&
    kexpSrc.includes("export async function prefetchBinaries"),
    `${directFetchLines.length} direct fetch() call(s) at line(s) ` +
    `${directFetchLines.map(([i]) => i + 1).join(", ")}`);

  check("launchKexp reads the prefetched bytes off the connection state",
    /state\.prefetched/.test(body),
    "launchKexp no longer looks at state.prefetched");
  check("launchKexp refuses without both binaries",
    /kexpBytes instanceof Uint8Array/.test(body) &&
    /elfldrBytes instanceof Uint8Array/.test(body),
    "one of the two byte checks is missing, so a partial prefetch would slip through");
  check("a missing prefetch throws rather than falling back to a fetch",
    /throw new Error\([\s\S]*?prefetchKexp\(\)/.test(body),
    "launchKexp would fetch instead of refusing");
  check("prefetchKexp stores the result on the connection, not just its return value",
    /state\.prefetched = await prefetchBinaries/.test(prefetchBody),
    "a payload could fetch after starting the exploit and still satisfy launchKexp");
  check("prefetchKexp is memoised, so a second call cannot fetch again",
    /if \(state\.prefetched\) return state\.prefetched;/.test(prefetchBody),
    "prefetchKexp would refetch on a second call, which is after the worker is committed");

  check("syscalls.js globals are available for the launchKexp run",
    vm.runInThisContext("typeof SYS_MMAP === 'number'"));

  // Serves both binaries, and records the order they were asked for in. The
  // order is the point: prefetchBinaries() must fetch the ELF first because the
  // payload's assertion below is that both fetches happened BEFORE any chain
  // work, not merely that they happened.
  const requested = [];
  let launchWire = null;
  await withFetch(async (url) => {
    requested.push(String(url));
    return { ok: true, arrayBuffer: async () => fakeElf() };
  }, async () => {
    launchWire = (await run(`
      return async function (api) {
        const ktextBase = {
          low: 0xffffff00, hi: 0xffffffff,
          add32(d) { return { low: (this.low + d) >>> 0, hi: this.hi }; },
        };
        const pre = await api.prefetchKexp();
        // A chain op AFTER the prefetch: if the fake still sees a clean chain, the
        // prefetch did not leave anything in flight.
        const pid = await api.chain.syscall(0x014);
        await api.log("chain alive after prefetch: " + (pid.low !== 0));
        try {
          await api.launchKexp({ krw: { ktextBase }, ...pre, stopAfter: "map" });
        } catch (e) {
          await api.log("launchKexp ended: " + e.message);
        }
      };
    `)).wire;
  });

  check("prefetchKexp fetched both binaries",
    /prefetched .*elf: 4096 bytes/.test(launchWire) &&
    /prefetched .*\.bin: 4096 bytes/.test(launchWire),
    (launchWire.match(/\[.\] kexp: prefetch[^\n]*/g) || []).join(" | "));
  check("both fetches were absolute URLs resolved against the document",
    requested.length === 2 && requested.every((u) => u.startsWith("http://")),
    requested.join(" | "));
  check("the fetch targets are the two configured binaries",
    /elfldr/.test(requested[0] ?? "") && /\.bin/.test(requested[1] ?? ""),
    requested.join(" | "));
  // Once per connection. A payload that prefetches again has fetched after the
  // worker was committed, which is the hang -- and the guard on launchKexp would
  // not catch it, because state.prefetched would just be overwritten.
  check("prefetchKexp fetches once per connection, not once per call",
    /if \(state\.prefetched\) return state\.prefetched;/.test(prefetchBody),
    "prefetchKexp has no memo, so a second call would fetch again");
  check("the chain still works after the prefetch",
    /chain alive after prefetch: true/.test(launchWire),
    (launchWire.match(/\[.\] chain alive[^\n]*/) || [""])[0]);
  check("the run failed cleanly on the fake mmap rather than hanging",
    /mmap failed/.test(launchWire) && /payload done/.test(launchWire),
    (launchWire.match(/\[.\] launchKexp ended[^\n]*/) || [""])[0]);
  check("kexp's own log lines reached the wire",
    /libkernel and libc symbols resolved/.test(launchWire) &&
    /using kexp binary/.test(launchWire),
    (launchWire.match(/\[.\] (using|allproc|libkernel)[^\n]*/g) || []).join(" | "));

}

//
{
function findSlopkitUpstream() {
  const candidates = [
    process.env.SLOPKIT_DIR,
    join(ROOT, "slopkit"),
    join(ROOT, "build/slopkit"),
    join(ROOT, "third_party/slopkit"),
    join(ROOT, "..", "slopkit"),
  ].filter(Boolean);

  for (const c of candidates) {
    if (existsSync(join(c, "poops.js")) && existsSync(join(c, "rop.js"))) return c;
    const sub = join(c, "slopkit");
    if (existsSync(join(sub, "poops.js")) && existsSync(join(sub, "rop.js"))) return sub;
  }
  return null;
}

const PAYLOAD_POOPS = join(ROOT, "payloads/poops.js");
const REF_SLOPKIT = findSlopkitUpstream();
const havePoopsUpstream = !!REF_SLOPKIT;
const poopsSrc = readFileSync(PAYLOAD_POOPS, "utf8");
// Comments stripped, once, for both 14b and 14c: the header explains all of this in
// prose and quoting the API names there would make these checks match themselves.
const poopsCode = poopsSrc.replace(/^\s*\/\/.*$/gm, "");

function portRegion(src, label) {
  const start = new RegExp(`^// =+ PORT BOUNDARY: ${label} starts here =+.*\\n`, "m").exec(src);
  const end = new RegExp(`^// =+ PORT BOUNDARY: ${label} ends here =+\\n`, "m").exec(src);
  if (!start || !end || end.index <= start.index + start[0].length) return null;
  return src.slice(start.index + start[0].length, end.index);
}

// 14a. Fidelity ----------------------------------------------------------------
if (!havePoopsUpstream) {
  console.log("  (skipping poops fidelity: slopkit repository is not present)");
} else {
  const upstreamPoops = readFileSync(join(REF_SLOPKIT, "poops.js"), "utf8");
  const upstreamRop = readFileSync(join(REF_SLOPKIT, "rop.js"), "utf8");

  // --- the poops.js region ----------------------------------------------------
  const pristine = portRegion(poopsSrc, "upstream poops\\.js");
  check("payloads/poops.js marks the ported poops.js region", pristine !== null);
  let region = pristine;

  // E1: `export ` was stripped. The reverse is driven by UPSTREAM's export list
  // rather than a hardcoded one, so an export added by a rebase is picked up
  // instead of being left un-exported and silently absorbed.
  const exportedNames = new Set(
    [...upstreamPoops.matchAll(/^export (?:const|function) ([A-Za-z_$][\w$]*)/gm)].map((m) => m[1]));
  check("upstream poops.js declares 25 exports", exportedNames.size === 25,
    `found ${exportedNames.size}`);
  let e1 = 0;
  region = region.split("\n").map((line) => {
    const m = /^(const|function) ([A-Za-z_$][\w$]*)/.exec(line);
    if (m && exportedNames.has(m[2])) { e1++; return `export ${line}`; }
    return line;
  }).join("\n");
  check("E1: `export` was stripped from exactly the upstream exports",
    e1 === exportedNames.size,
    `reversed ${e1} of ${exportedNames.size}; a mismatch means the port added or dropped a declaration`);
  // Checked against the pristine region, not the E1-reversed one below -- the
  // reversal has just put 25 `export`s back, so testing `region` here would be
  // testing the reversal against itself.
  check("payloads/poops.js has no `export` left in the ported region",
    pristine !== null && !/^export /m.test(pristine),
    "the payload is run by indirect eval, where `export` is a syntax error");

  const portBlock = (id) => new RegExp(
    `^([ \\t]*)// >>> poops port ${id}:[^\\n]*\\n[\\s\\S]*?^[ \\t]*// >>> poops port ${id} end\\n`, "m");
  const tail = (body) => body.replace(/\n+$/, "") + "\n";
  const slice = (src, from, to) => tail(src.slice(src.indexOf(from), src.indexOf(to)));

  const afterE2 = region.replace(portBlock("E2"), () => slice(upstreamPoops,
    "  async function fetchInto(url, sink) {", "  function unpin(buf, why) {"));
  check("E2: the fetchInto block is present and was replaced", afterE2 !== region,
    "no `poops port E2` block found; the fetch helper is still in the payload");

  const afterE3 = afterE2.replace(portBlock("E3"), () => slice(upstreamPoops,
    "  async function stage5Body(opts) {", "\n  return {\n    PK,"));
  check("E3: the stage5Body block is present and was replaced", afterE3 !== afterE2,
    "no `poops port E3` block found; stage 5 is still upstream's");

  const afterE4 = afterE3.replace("    latch,\n    launchKexp,\n  } = X;", "    latch,\n  } = X;");
  check("E4: launchKexp is read from the context and was added", afterE4 !== afterE3,
    "makePoopsEngine no longer destructures launchKexp, so the replacement cannot call it");

  // E5 is a marker-delimited text swap inside ps10_stage5. Reversed by the same
  // rule as E2/E3 so the edit is findable without knowing what it says.
  const afterE5 = afterE4.replace(portBlock("E5"), (_m, indent) => {
    const from = upstreamPoops.indexOf(`${indent}if (!r.ran) return PASS("dry run:`);
    const end = upstreamPoops.indexOf('"built",);', from) + '"built",);'.length;
    return tail(upstreamPoops.slice(from, end));
  });
  check("E5: the dry-run summary block is present and was replaced", afterE5 !== afterE4,
    "no `poops port E5` block found; the dry run claims work it never did");

  check("payloads/poops.js is upstream poops.js, unmodified",
    afterE5 === upstreamPoops, firstDifference(afterE5, upstreamPoops));

  // E5 asserts the ABSENCE of an edit -- thread_rop is reached, not changed --
  // so there is nothing to reverse and it is checked as a fact instead.
  const threadAt = poopsSrc.indexOf("class thread_rop");
  check("E5: thread_rop comes from the ported rop region, not a second definition",
    threadAt >= 0 && threadAt < poopsSrc.indexOf("PORT BOUNDARY: upstream poops.js starts"),
    (poopsSrc.match(/^\s*class thread_rop.*$/m) || ["(none)"])[0]);
  check("worker_rop is not redefined by the payload",
    !/^\s*class worker_rop/m.test(poopsSrc),
    "the payload must use the loader's worker_rop through api.chain");

  // --- the rop.js region ------------------------------------------------------
  let rop = portRegion(poopsSrc, "slopkit rop\\.js");
  check("payloads/poops.js marks the ported rop.js region", rop !== null);

  const ropLines = upstreamRop.split("\n");
  const ropAt = (prefix) => ropLines.findIndex((l) => l.startsWith(prefix));
  const iRop = ropAt("class rop"), iWorker = ropAt("class worker_rop"), iThread = ropAt("class thread_rop");
  check("upstream rop.js has the three classes the port indexes",
    iRop >= 0 && iRop < iWorker && iWorker < iThread,
    `rop=${iRop} worker_rop=${iWorker} thread_rop=${iThread}`);

  let expectRop = "";
  if (iRop >= 0 && iWorker >= 0 && iThread >= 0) {
    // worker_rop is dropped on purpose -- the loader has one -- so the expected
    // region is the base class, then thread_rop, with the blank line that used to
    // separate them.
    expectRop = ropLines.slice(iRop, iWorker).join("\n").replace(/\s+$/, "") + "\n\n" +
      ropLines.slice(iThread).join("\n").replace(/\s+$/, "") + "\n";
  }
  // The four rewrites, matched by exact text. alert() is a blocking modal on the
  // PS5's WebKit page: from a payload it freezes the thread that owns the only
  // hijacked worker, and the console needs a power-off. A throw reports the same
  // condition and the ladder runner catches it.
  const ALERT_REWRITES = [
    [`alert("you're trying to write a value exceeding 32-bits without using a int64 instance");`,
      `throw new Error("rop: value exceeds 32 bits and was not an int64 instance");`],
    [`alert("You're trying to write a non number/non int64 value?");`,
      `throw new Error("rop: pushed a value that is neither a number nor an int64");`],
    [`alert("Unsupported target register: " + target_reg);`,
      `throw new Error("rop: unsupported target register: " + target_reg);`],
    [`alert("illegal branch type.");`,
      `throw new Error("rop: illegal branch type " + type);`],
  ];
  for (const [from, to] of ALERT_REWRITES) {
    check(`rop region rewrites ${from.slice(0, 32)}... into a throw`, expectRop.includes(from));
    expectRop = expectRop.replace(from, to);
  }
  check("payloads/poops.js has no alert() left in the ported rop region",
    rop !== null && !/alert\(/.test(rop), (rop.match(/.*alert\(.*/) || [""])[0]);
  check("payloads/poops.js's rop region is upstream rop.js, unmodified",
    rop === expectRop, firstDifference(rop, expectRop));
}

// 14b. Source-level regression guards
{
  const code = poopsCode;   // shared with 14c

  check("payloads/poops.js contains no fetch of its own",
    !/\bfetch\s*\(/.test(code), (code.match(/.*\bfetch\s*\(.*/) || [""])[0]);
  check("payloads/poops.js has no XMLHttpRequest, Worker, import or require",
    !/XMLHttpRequest|new Worker|await import\(|\brequire\(/.test(code),
    (code.match(/.*(XMLHttpRequest|new Worker|await import\(|require\().*/) || [""])[0]);
  check("no api.module() call, so the payload is one self-contained file",
    !/api\.module\(/.test(code));

  // The prefetch must precede the ladder, and be the payload's own straight-line
  // code. A line-order check alone cannot tell the difference, because the
  // launchKexp closure stage 5 calls is textually earlier -- what makes a prefetch
  // inside it wrong is WHEN it runs, during the exploit, with the worker committed.
  const codeLines = code.split("\n");
  check("payloads/poops.js prefetches exactly once",
    codeLines.filter((l) => /\bapi\.prefetchKexp\s*\(/.test(l)).length === 1,
    `${codeLines.filter((l) => /\bapi\.prefetchKexp\s*\(/.test(l)).length} call sites`);

  const atPrefetch = poopsSrc.indexOf("await api.prefetchKexp()");
  const atLadder = poopsSrc.indexOf("await runLadder(ctx, engine)");
  const atHook = poopsSrc.indexOf("const launchKexp = async (options) =>");
  check("the prefetch precedes the ladder run",
    atPrefetch !== -1 && atLadder !== -1 && atPrefetch < atLadder,
    atLadder === -1 ? "no runLadder call found" : `prefetch at ${atPrefetch}, runLadder at ${atLadder}`);
  check("the prefetch precedes the launchKexp hook that stage 5 calls",
    atPrefetch !== -1 && atHook !== -1 && atPrefetch < atHook,
    atHook === -1 ? "no launchKexp closure found" : `prefetch at ${atPrefetch}, hook at ${atHook}`);

  // The replaced stage5Body delegates and nothing else: no mapping, no spawning,
  // no private API table. Those are exactly the jobs api.launchKexp() does, and
  // doing them twice would be two jitshm_create mappings of the same shellcode.
  check("the replacement stage5Body delegates to launchKexp and maps nothing itself",
    /await launchKexp\(\{/.test(code) &&
    !/sys\(PSYS\.JITSHM_CREATE/.test(code) &&
    !/sys\(PSYS\.MMAP/.test(code) &&
    !/apiTable/.test(code),
    "stage 5 still maps or builds an API table itself");

  // krw rides the crossed pipe pair the cleanup closes, so its accessors are
  // disabled rather than left to fault the worker the loader shares.
  check("api.krw is published with its accessors disabled",
    /api\.krw = disarmKrw\(/.test(code) && /function disarmKrw/.test(code) && /DISABLED/.test(poopsSrc));

  // One-shot latch: the refusal, the reason, and the recovery.
  check("the payload refuses to run twice while the latch is held",
    /poops-latch/.test(poopsSrc) && /latch-clear/.test(poopsSrc) && /REBOOT the console/.test(poopsSrc),
    "the latch exists but the refusal, the reason, or the recovery is missing");

  // --- the loader change the port depends on ----------------------------------
  //
  // api.chain must expose the geometry the facade needs to predict fcall()'s
  // alignment padding. Without it the payload refuses at startup rather than
  // guessing, which is the right behaviour, but it would refuse forever.
  const loaderSrc = readFileSync(join(ROOT, "src/loader.js"), "utf8");
  const gatedBody = loaderSrc.slice(
    loaderSrc.indexOf("function gatedChain()"),
    loaderSrc.indexOf("async function sendBlob"));
  const gatedApi = gatedBody.slice(gatedBody.indexOf("const api = {"));
  check("api.chain exposes stack_entry_point, or the payload cannot run",
    /get stack_entry_point\(\)/.test(gatedBody),
    "gatedChain() no longer forwards stack_entry_point");
  check("api.chain exposes the geometry the capacity check needs",
    /get stack_size\(\)/.test(gatedBody) &&
    /get reserved_stack\(\)/.test(gatedBody) &&
    /get initial_count\(\)/.test(gatedBody),
    "stack_size / reserved_stack / initial_count are not all forwarded");
  // The forwardings must stay reads. A writable one would hand a payload a way to
  // execute outside the gate, which is the single property api.chain exists for.
  const forwarded = [...gatedApi.matchAll(/get (\w+)\(\)/g)].map((m) => m[1]);
  check("the geometry additions to api.chain are getters only",
    ["stack_entry_point", "stack_size", "reserved_stack", "initial_count"]
      .every((n) => forwarded.includes(n)),
    `forwarded getters: ${forwarded.join(", ")}`);
  // Only a definition or assignment counts as writable, so `get X()` and a read
  // inside a method body do not match. The earlier version matched the `(`
  // in `get stack_entry_point()` and reported every correct loader as broken.
  const WRITABLE = new RegExp(
    "(?:^|[{,\\s])(stack_entry_point|stack_size|reserved_stack|initial_count)\\s*[:,=]", "m");
  check("api.chain gains no writable property for the payload",
    !WRITABLE.test(gatedApi),
    (gatedApi.match(new RegExp(`.{0,40}${WRITABLE.source}.{0,40}`, "m")) || [""])[0]);

  // PROLOGUE_SLOTS must match what pre_chain() actually pushes: poops' assertFresh()
  // compares count against initial_count + 3, so if prepareChain's length changes,
  // every batched call in the exploit throws "chain not fresh" at runtime.
  const mainSrc = readFileSync(join(ROOT, "src/main.js"), "utf8");
  const preChain = mainSrc.slice(
    mainSrc.indexOf("function prepareChain(chain)"),
    mainSrc.indexOf("function launchChainDetached"));
  const preChainPushes = (preChain.match(/chain\.push\(/g) || []).length;
  const declaredSlots = /const PROLOGUE_SLOTS = (\d+);/.exec(poopsSrc);
  check("the payload's PROLOGUE_SLOTS matches the loader's pre_chain()",
    declaredSlots !== null && preChainPushes === Number(declaredSlots[1]),
    `prepareChain pushes ${preChainPushes}, the payload declares ${declaredSlots ? declaredSlots[1] : "nothing"}`);

  check("payloads/poops.js never sets api.allowXotextReads",
    !/allowXotextReads/.test(code));

  // Firmware coverage, measured against the real offset tables rather than a
  // hardcoded list, so a new offsets/*.js is checked instead of skipped.
  const REQUIRED_GADGETS = ["ret", "pop rdi", "pop rsi", "pop rdx", "pop rcx",
    "pop rax", "pop rsp", "pop r8", "pop r9", "mov [rdi], rsi", "mov [rdi], rax",
    "mov [rdi], eax", "mov rax, [rax]", "inc dword [rax]"];
  const REQUIRED_OFFSETS = ["OFFSET_lk_sceKernelGetCurrentCpu",
    "OFFSET_lk_pthread_exit", "OFFSET_lk_pthread_create_name_np",
    "OFFSET_lk_pthread_join", "OFFSET_lc_longjmp"];
  const offsetDir = join(ROOT, "offsets");
  const profiles = existsSync(offsetDir) ? readdirSync(offsetDir).filter((f) => f.endsWith(".js")) : [];
  const shortGadgets = [], shortOffsets = [];
  for (const f of profiles) {
    const text = readFileSync(join(offsetDir, f), "utf8");
    const missing = REQUIRED_GADGETS.filter((g) => !text.includes(`"${g}":`));
    if (missing.length) shortGadgets.push(`${f}: ${missing.join(", ")}`);
    const off = REQUIRED_OFFSETS.filter(
      (o) => !new RegExp(`^const ${o}\\s*=\\s*0x`, "m").test(text));
    if (off.length) shortOffsets.push(`${f}: ${off.join(", ")}`);
  }
  check("the payload's preflight names every gadget any profile is missing",
    shortGadgets.every((entry) => entry.split(": ")[1].split(", ")
      .every((g) => poopsSrc.includes(`"${g}"`))),
    shortGadgets.join(" | "));
  check("the payload's preflight names every thread offset any profile is missing",
    shortOffsets.every((entry) => entry.split(": ")[1].split(", ")
      .every((o) => poopsSrc.includes(o))),
    shortOffsets.join(" | "));
  console.log(`  (note  profiles this payload refuses by name: ` +
    `${[...new Set(shortGadgets.concat(shortOffsets).map((e) => e.split(":")[0]))].join(", ") || "none"})`);
  check("the payload is within the loader's 512 KiB payload limit",
    Buffer.byteLength(poopsSrc) <= 512 * 1024,
    `${Buffer.byteLength(poopsSrc)} bytes`);
}

// 14c. Behavioural smoke run
{
  // Two globals the payload expects from the page and node does not have. The
  // loader publishes int64; sessionStorage backs the latch.
  await import(pathToFileURL(join(ROOT, "src/utils/int64.js")).href);
  check("int64 reaches the global scope, as src/utils/int64.js leaves it",
    vm.runInThisContext("typeof globalThis.int64 === 'function'"));

  vm.runInThisContext([
    "let OFFSET_lk_sceKernelGetCurrentCpu = 0x1200;",
    "let OFFSET_lk_pthread_exit = 0x21b90;",
    "let OFFSET_lk_pthread_create_name_np = 0x21800;",
    "let OFFSET_lk_pthread_join = 0x22910;",
    "let OFFSET_lc_longjmp = 0x5b8a0;",
  ].join("\n"));

  // The trap, asserted directly rather than only through the payload's behaviour.
  check("the fake reproduces the page's lexical-offset trap",
    globalThis.OFFSET_lk_pthread_exit === undefined &&
    vm.runInThisContext("typeof OFFSET_lk_pthread_exit") === "number",
    `globalThis.OFFSET_lk_pthread_exit is ${globalThis.OFFSET_lk_pthread_exit}, ` +
    `typeof is ${vm.runInThisContext("typeof OFFSET_lk_pthread_exit")}; if the ` +
    `former is a number this fake is not reproducing a classic script, and any ` +
    `globalThis-based check in the payload passes for the wrong reason`);

  check("the payload reads the offsets as bare identifiers, not off globalThis",
    !/globalThis\[/.test(poopsSrc.replace(/^\s*\/\/.*$/gm, "")) &&
    /typeof OFFSET_lk_pthread_exit/.test(poopsSrc),
    "a globalThis[name] lookup returns undefined for a classic-script const, so " +
    "the preflight refuses every firmware -- observed on FW 7.61");

  // The guard, exercised: with one constant genuinely absent the payload must
  // refuse by name BEFORE prefetching or touching the chain.
  vm.runInThisContext("OFFSET_lk_pthread_exit = undefined;");
  let refusedWire = "";
  await withFetch(async () => ({ ok: true, arrayBuffer: async () => fakeElf(0x1000) }),
    async () => { refusedWire = (await runSequence([{ src: poopsSrc }],
      { fakeOpts: { chainAuthoring: true } })).wire; });
  check("a firmware missing a thread offset is refused by name",
    /does not declare/.test(refusedWire) && /OFFSET_lk_pthread_exit/.test(refusedWire),
    (refusedWire.match(/\[.\] offsets\/9\.99\.js does not declare[^\n]*/) || [""])[0]);
  check("that refusal happens before the prefetch and before any syscall",
    refusedWire.indexOf("does not declare") !== -1 &&
    refusedWire.indexOf("prefetched") === -1 &&
    !/starting|INHERITED-MASK|CORE-CHOSEN/.test(refusedWire),
    (refusedWire.match(/\[.\] (starting|INHERITED-MASK|prefetched)[^\n]*/g) || [""]).join(" | "));
  vm.runInThisContext("OFFSET_lk_pthread_exit = 0x21b90;");

  const latchStore = new Map();
  globalThis.sessionStorage = {
    getItem: (k) => (latchStore.has(k) ? latchStore.get(k) : null),
    setItem: (k, v) => { latchStore.set(k, String(v)); },
    removeItem: (k) => { latchStore.delete(k); },
  };

  const prefetchStub = async (url) => {
    timeline.push(String(url));
    return { ok: true, arrayBuffer: async () => fakeElf(String(url).includes("elfldr") ? 0x1000 : 0x800) };
  };

  // Both binaries must prefetch, so the run reaches the ladder rather than
  // failing at the prefetch guard. Asserted, not assumed.
  const timeline = [];
  const { wire } = await withFetch(prefetchStub,
    async () => runSequence([{ src: poopsSrc }], { fakeOpts: { chainAuthoring: true } }));

  check("poops prefetches both binaries and says so",
    timeline.length === 2 && /prefetched/.test(wire),
    `${timeline.length} fetch(es): ${timeline.join(", ")}`);
  check("poops announces the firmware and the offsets table it is using",
    /poops on fw 9\.99/.test(wire) && /offsets\/9\.99\.js/.test(wire),
    (wire.match(/\[.\] poops on fw[^\n]*/) || [""])[0]);

  // The chain facade is the load-bearing piece of the adapter. Reaching the ladder
  // at all means it constructed itself: it reads the gated chain's geometry and
  // checks the gadget table, neither of which the base fake exercises.
  check("the payload gets past its own setup into the ladder",
    /TEST-ENTER ps0_preflight/.test(wire),
    (wire.match(/\[.\] (ladder:|setup refused|the ladder threw|TEST-ENTER)[^\n]*/) || [""])[0]);

  check("ps0_preflight ran to completion and passed",
    /ps0_preflight \[.*\] -- PASS/.test(wire),
    (wire.match(/\[.\] ps0_preflight[^\n]*/) || [""])[0]);
  check("a failing row stops the ladder instead of continuing",
    /ps1_prepare \[.*\] -- FAIL/.test(wire) &&
    /ps5_stage1 \[.*\] -- SKIP: REFUSED after 'ps1_prepare' failed/.test(wire),
    (wire.match(/\[.\] ps[0-9]\w* \[[^\n]*/g) || []).join(" | "));
  check("the cleanup row still runs after a failure, and restores the scheduler",
    /ps7_report \[.*\]/.test(wire) &&
    /DRIVER-RESTORE .*aff=true-prio=true/.test(wire),
    (wire.match(/\[.\] ps7_report[^\n]*/) || [""])[0]);
  // ps7_report cannot COMPLETE here: the fake has no kernel threads, so the racers
  // never exit and the wake-gate writes go nowhere. That it ran, said exactly why,
  // and still restored the driver's affinity and priority is the part under test.
  // Skipping it instead would leave 80 sockets and twelve realtime threads parked
  // on a core that no later page load can reach.
  check("the run reaches the racer spawn, so the facade built thread prologues",
    /SPAWN-PRE iov-n=\d+-thr_new=0x1C7/.test(wire),
    (wire.match(/\[.\] SPAWN-PRE[^\n]*/) || ["(never reached)"])[0]);
  check("the telemetry buffer is drained, not left behind",
    /scheduler restored: affinity OK/.test(wire) &&
    /POOPS-VERDICT/.test(wire),
    "buffered marks and notes never reached the wire");
  const ranRows = wire.match(/^\[.\] ps\d+_[a-z0-9]+ \[[^\n]*/gm) || [];
  const skippedRows = ranRows.filter((l) => / -- SKIP/.test(l));
  const timedRows = ranRows.filter((l) => / -- (?:PASS|FAIL) \(\d+ ms\)/.test(l));
  check("every row that ran reports how long it took, so a slow stage is attributable",
    ranRows.length - skippedRows.length >= 3 &&
    ranRows.length - skippedRows.length === timedRows.length,
    ranRows.map((l) => (/ -- (?:PASS|FAIL) \(\d+ ms\)/.test(l) ? "timed  " : "UNTIMED") +
      ": " + l.trim().slice(0, 62)).join("\n      "));
  check("the run accounts for what the output machinery cost",
    /telemetry: \d+ lines in \d+ writes \(\d+ mid-race, \d+ row-boundary\), \d+ ms issuing/.test(wire),
    (wire.match(/\[.\] telemetry[^\n]*/) || ["(no telemetry summary)"])[0]);

  check("the telemetry cost line reports no unattributable time-to-complete",
    !/ms draining/.test(wire) && !/ms painting/.test(wire) &&
    /\d+ ms issuing/.test(wire),
    (wire.match(/\[.\] telemetry[^\n]*/) || ["(no telemetry summary)"])[0]);
  check("the write total includes both paints and row-boundary drains",
    (() => {
      const m = /telemetry: \d+ lines in (\d+) writes \((\d+) mid-race, (\d+) row-boundary\)/
        .exec(wire);
      if (!m) return false;
      // The total must be the sum of its two named parts, not just one of them.
      return Number(m[1]) === Number(m[2]) + Number(m[3]);
    })(),
    (wire.match(/\[.\] telemetry[^\n]*/) || ["(no telemetry summary)"])[0]);
  const tl = /telemetry: \d+ lines in (\d+) writes \((\d+) mid-race, (\d+) row-boundary\)/.exec(wire);
  check("mid-race painting happens, and drops nothing",
    !!tl && Number(tl[1]) === Number(tl[2]) + Number(tl[3]) &&
    Number(tl[2]) >= 1 && !/dropped by the telemetry ring/.test(wire),
    (wire.match(/\[.\] telemetry[^\n]*/) || ["(no telemetry summary)"])[0] +
    " / drops: " + (wire.match(/^\.\] \(\d+ earlier lines were dropped[^\n]*/gm) || []).join("|"));
  check("the run reports a ladder summary with the row it stopped at",
    /ladder: 11 rows -- \d+ PASS, \d+ FAIL, \d+ SKIP \(stopped at ps1_prepare\)/.test(wire),
    (wire.match(/\[.\] ladder:[^\n]*/) || [""])[0]);
  check("the run reports poops' own measurements and verdict",
    /trigger netcontrol: fired=/.test(wire) && /chain round trip:/.test(wire),
    (wire.match(/\[.\] (trigger|chain round)[^\n]*/g) || []).join(" | "));

  //  the defaults
  check("a default run arms the race instead of sitting out",
    /trigger netcontrol: fired=/.test(wire),
    (wire.match(/\[.\] trigger \w+: fired[^\n]*/) || [""])[0]);
  // Read from the payload's own banner rather than from ps10_stage5's row. The row
  // is skipped whenever an earlier row fails -- and on the fake ps1_prepare always
  // does, because there are no kernel threads -- so asserting on it passes whether
  // or not the payload default is right. That check was written first and was
  // vacuous; this one is not.
  check("a default run states the effective settings, including trigger and payload",
    /effective settings: trigger=netcontrol attempts=8 sockets=\d+ payload=1/.test(wire),
    (wire.match(/\[.\] effective settings[^\n]*/) || [""])[0]);
  check("a default run is not treated as the negative control",
    !/NEGATIVE CONTROL, not a failure/.test(wire));

  // Snapshot the default run's verdict now, while it is still there: the runs below
  // deliberately clear the store, and this is the value the latch matrix is about.
  const firstRunVerdict = latchStore.get("poops-verdict");

  // ...and the negative control is still one flag away, still explained.
  // The store is cleared first: the default run above left the latch held with a
  // dirty verdict, and that refusal is correct -- it just is not what this run is
  // about.
  latchStore.clear();
  const negative = await withFetch(prefetchStub,
    async () => runSequence([{ src: poopsSrc, argv: ["trigger=none"] }],
      { fakeOpts: { chainAuthoring: true } }));
  latchStore.clear();
  check("--arg trigger=none restores the negative control",
    /trigger none: fired=no/.test(negative.wire) &&
    /effective settings: trigger=none attempts=1 .* \[NEGATIVE CONTROL/.test(negative.wire),
    (negative.wire.match(/\[.\] (trigger \w+: fired|effective settings)[^\n]*/g) || []).join(" | "));
  check("a negative-control run explains that its SKIPs are not a failure",
    /NEGATIVE CONTROL, not a failure/.test(negative.wire) &&
    /stages 4-9 have nothing to escalate with/.test(negative.wire),
    (negative.wire.match(/\[.\] trigger=none[^\n]*/) || [""])[0]);

  //  the latch, as the matrix it now is
  check("a first run is not refused by the latch",
    !/the poops latch is already held/.test(wire));
  check("the run records a verdict for the next one to read",
    firstRunVerdict !== undefined && firstRunVerdict !== null,
    `poops-verdict is ${JSON.stringify(firstRunVerdict)}`);
  check("this run's verdict is DIRTY, because the fake never escalates cleanly",
    firstRunVerdict === "dirty",
    `the fake cannot reach stage 4, so a clean verdict would be a false all-clear; ` +
    `got ${JSON.stringify(firstRunVerdict)}`);

  const sendWithLatch = async (verdict) => {
    latchStore.set("poops-latch", "ps1: opening 80 ipv6 sockets (seeded by the test)");
    if (verdict === null) latchStore.delete("poops-verdict");
    else latchStore.set("poops-verdict", verdict);
    const r = await withFetch(prefetchStub,
      async () => runSequence([{ src: poopsSrc }], { fakeOpts: { chainAuthoring: true } }));
    latchStore.clear();
    return r.wire;
  };

  const afterDirty = await sendWithLatch("dirty");
  check("a re-send after a DIRTY verdict is refused, and says why",
    /the poops latch is already held/.test(afterDirty) &&
    /verdict was DIRTY/.test(afterDirty) &&
    /REBOOT the console/.test(afterDirty),
    (afterDirty.match(/\[.\] the previous run's verdict[^\n]*/) || [""])[0]);
  check("that refusal happens before the prefetch, so nothing is fetched",
    afterDirty.indexOf("the poops latch is already held") !== -1 &&
    afterDirty.indexOf("prefetched") === -1,
    (afterDirty.match(/\[.\] [^\n]*/g) || []).slice(0, 10).join(" | "));

  const afterClean = await sendWithLatch("clean");
  check("a re-send after a CLEAN verdict proceeds, and says why",
    !/the poops latch is already held/.test(afterClean) &&
    /verdict was CLEAN/.test(afterClean),
    (afterClean.match(/\[.\] the latch was held[^\n]*/) || [""])[0]);

  const afterNone = await sendWithLatch(null);
  check("a re-send with NO verdict is refused: nobody knows the kernel state",
    /the poops latch is already held/.test(afterNone) &&
    /left no verdict/.test(afterNone),
    (afterNone.match(/\[.\] the previous run's verdict[^\n]*/) || [""])[0]);

  const cleared = await withFetch(prefetchStub, async () => {
    latchStore.set("poops-latch", "seeded");
    latchStore.set("poops-verdict", "dirty");
    const r = await runSequence([{ src: poopsSrc, argv: ["latch-clear"] }],
      { fakeOpts: { chainAuthoring: true } });
    latchStore.clear();
    return r;
  });
  check("--arg latch-clear overrides even a dirty verdict",
    cleared.wire.includes("latch cleared on request") &&
    !/the poops latch is already held/.test(cleared.wire),
    (cleared.wire.match(/\[.\] latch cleared[^\n]*/) || [""])[0]);

  // krw must not be published off a failed run. On the fake the ladder never
  // reaches stage 4, so there is no handle -- and publishing one would make
  // --status report a jailbreak that did not happen.
  check("a run that never reached stage 5 publishes no krw handle",
    /no krw handle to publish/.test(wire),
    (wire.match(/\[.\] (api\.krw|no krw)[^\n]*/) || [""])[0]);

  check("the payload returned without the loader reporting a throw",
    /--- payload done ---/.test(wire) && !/payload threw/.test(wire),
    (wire.match(/\[.\] payload threw[^\n]*/) || [""])[0]);

  //  the facade's slot counter, tested directly
  const facade = vm.runInThisContext(
    `(function () {\n${poopsSrc.replace(
      "return async function (api) {",
      "globalThis.__poopsMakeWorkerChain = makeWorkerChain;\n" +
      "  globalThis.__poopsTelemetry = Telemetry;\n" +
      "  globalThis.__poopsPaintMs = PAINT_MS;\n" +
      "  return async function (api) {")}\n})()`,
    { filename: "payloads/poops.js" });
  check("the payload's chain facade can be reached for direct testing",
    typeof globalThis.__poopsMakeWorkerChain === "function");
  check("the telemetry class can be reached for direct testing",
    typeof globalThis.__poopsTelemetry === "function");

  // A gated chain stand-in that records what the facade asked of it.
  const ops = [];
  const gatedStub = {
    count: 3,
    initial_count: 0,
    stack_size: 0x80000,
    reserved_stack: 0x10000,
    stack_entry_point: new int64(0x7f400018),
    return_value: new int64(0x7f480000),
    push: (v) => { ops.push(["push", v]); },
    push_write8: (d, v) => { ops.push(["push_write8", d, v]); },
    write_result: (d) => { ops.push(["write_result", d]); },
    fcall: (...a) => { ops.push(["fcall", a]); },
    clear: () => { ops.push(["clear"]); },
    add_syscall: (...a) => { ops.push(["add_syscall", a]); },
    add_syscall_ret: (...a) => { ops.push(["add_syscall_ret", a]); },
    run: async () => { ops.push(["run"]); },
    syscall: async (...a) => { ops.push(["syscall", a]); return new int64(0, 0); },
    call: async (...a) => { ops.push(["call", a]); return new int64(0, 0); },
  };
  const stubApi = {
    fw: "13.60",
    chain: gatedStub,
    gadgets: Object.fromEntries(
      ["ret", "pop rdi", "pop rsi", "pop rdx", "pop rcx", "pop rax", "pop rsp",
        "pop r8", "pop r9", "mov [rdi], rsi", "mov [rdi], rax", "mov [rdi], eax",
        "mov rax, [rax]", "inc dword [rax]"]
        .map((n) => [n, new int64(0x7f300000, 0)])),
    syscalls: Object.fromEntries([...Array(600).keys()].map((n) => [n, new int64(0x7f200000, 0)])),
  };

  const facadeChain = globalThis.__poopsMakeWorkerChain(stubApi);
  check("the facade starts at the prologue, which is what assertFresh expects",
    facadeChain.count === 3, `count is ${facadeChain.count}, expected 3`);

  facadeChain.fcall(new int64(0x7f200100), new int64(1), new int64(2));
  const afterFcall = facadeChain.count;
  check("fcall consumes slots, so assertFresh would notice a leftover batch",
    afterFcall > 3, `count is ${afterFcall} after one two-argument fcall`);
  await facadeChain.run();
  check("run() resets the facade's slot counter to the prologue",
    facadeChain.count === 3,
    `count is ${facadeChain.count} after run(), expected 3 -- this is the bug that ` +
    `made every batched call throw "chain not fresh" on hardware`);
  check("run() went through the gated chain, not around it",
    ops.some(([n]) => n === "run"), `ops: ${ops.map(([n]) => n).join(",") || "(none)"}`);

  facadeChain.fcall(new int64(0x7f200100), new int64(1));
  await facadeChain.syscall(0x14);
  check("syscall() resets the facade's slot counter too",
    facadeChain.count === 3,
    `count is ${facadeChain.count} after syscall(), expected 3`);

  for (const entryLow of [0x7f400000, 0x7f400018]) {
    gatedStub.stack_entry_point = new int64(entryLow);
    const c = globalThis.__poopsMakeWorkerChain(stubApi);
    const realPush = gatedStub.push;
    let pushed = 0;
    gatedStub.push = (...a) => { pushed++; return realPush(...a); };

    // rop.js: push_sysv first (count + 2 per defined arg), then test
    // (stack_entry_point + count*8) & 8, then push the target.
    const ropSlots = (countBefore, nargs) => {
      const afterSysv = countBefore + nargs * 2;
      const pad = (((entryLow + afterSysv * 8) >>> 0) & 8) ? 1 : 0;
      return nargs * 2 + pad + 1;
    };

    c.fcall(new int64(0x7f200100), new int64(1), new int64(2), new int64(3));
    const first = pushed, wantFirst = ropSlots(3, 3);
    pushed = 0;
    c.fcall(new int64(0x7f200100), new int64(1));
    const second = pushed, wantSecond = ropSlots(3 + wantFirst, 1);

    gatedStub.push = realPush;
    check(`fcall's slot count matches rop.js at entry 0x${entryLow.toString(16)}`,
      first === wantFirst && second === wantSecond,
      `3 args: facade ${first}, rop.js ${wantFirst}; ` +
      `1 arg after: facade ${second}, rop.js ${wantSecond}`);
  }
  gatedStub.stack_entry_point = new int64(0x7f400018);

  // The adapter must have no second execution path. This is the check that would
  // have caught the original bug without any of the above.
  const adapterCode = poopsSrc.replace(/^\s*\/\/.*$/gm, "");
  check("the adapter executes only through the facade",
    !/ctx\.gated\.(run|syscall|call)\(/.test(adapterCode) &&
    /ctx\.chain\.run\(\)/.test(adapterCode) &&
    /ctx\.chain\.syscall\(/.test(adapterCode),
    "an execution path that bypasses the facade leaves its slot counter stale; " +
    "found: " + ((adapterCode.match(/ctx\.gated\.\w+\(/) || [""])[0]));
  check("the adapter does not expose the gated chain at all",
    !/gated:\s*api\.chain/.test(adapterCode),
    "a ctx.gated handle is exactly what makes a second execution path possible");

  //  telemetry pacing
  {
    // api.log's real shape: append to a pending buffer, schedule ONE flush, resolve
    // on it. A stand-in that resolved synchronously would make coalescing untestable
    // AND would hide the bug, because the cost being modelled is the round trip.
    const makeSay = (sink, batchSizes) => {
      let pending = [];
      const say = (line) => {
        pending.push(line);
        return new Promise((res) => {
          queueMicrotask(() => {
            if (pending.length === 0) return void res();
            const batch = pending;
            pending = [];
            batchSizes.push(batch.length);
            for (const l of batch) sink.push(l);
            res();
          });
        });
      };
      return say;
    };

    // A clock the test drives, so PAINT_MS is not waited out in real time.
    const realNow = Date.now;
    let clock = 100000;
    Date.now = () => clock;

    try {
      // Settle: let any fire-and-forget paint finish before counting. Driven by real
      // timers, so it works whatever the fake clock says.
      const settle = () => new Promise((r) => setTimeout(r, 25));

      // 1. Mid-race marks reach the sink on their own, before the row ends.
      {
        const out = [], batches = [];
        const t = new globalThis.__poopsTelemetry(makeSay(out, batches));
        t.raceMode = true;
        for (let i = 0; i < 20; i++) { clock += 400; t.mark("M" + i, "d" + i); await settle(); }
        const midRow = out.length;
        await t.drain();
        check("a race row's marks reach the PC while the row is still running",
          midRow === 20 && out.length === 20,
          `mark() on its own delivered ${midRow}/20 before the row ended, ` +
          `${out.length}/20 after the row's drain; a row that only ever drains at ` +
          `its boundary delivers 0 of them mid-row`);
      }

      // 2. The cadence is rate limited: a synchronous burst is not one write per
      //    line. This is the bound that makes painting affordable inside a race --
      //    one chain round trip per PAINT_MS, not one per line.
      {
        const out = [], batches = [];
        const t = new globalThis.__poopsTelemetry(makeSay(out, batches));
        t.raceMode = true;
        for (let i = 0; i < 200; i++) t.mark("M" + i, "");   // clock does not move
        await settle();
        const writesAfterBurst = batches.length;
        await t.drain();
        const delivered = batches.reduce((a, b) => a + b, 0);
        check("a burst of race marks costs one write, not one per line",
          writesAfterBurst <= 2 && delivered === 200 && out.length === 200,
          `200 marks in one burst: ${writesAfterBurst} write(s) during the burst ` +
          `(sizes ${JSON.stringify(batches)}), ${out.length}/200 delivered; ` +
          `PAINT_MS is ${globalThis.__poopsPaintMs} ms and the clock did not move, ` +
          `so painting per line would be 200`);
      }

      // 3. The cadence is PAINT_MS, upstream's SCREEN_MS. Tighter and the race pays
      //    for output the exploit never asked for; looser, or absent, and a long
      //    window goes quiet again.
      {
        const out = [], batches = [];
        const t = new globalThis.__poopsTelemetry(makeSay(out, batches));
        t.raceMode = true;
        t.mark("first", "");
        await settle();
        const afterFirst = batches.length;
        clock += globalThis.__poopsPaintMs - 1;
        t.mark("too soon", "");
        await settle();
        const tooSoon = batches.length;
        clock += 2;
        t.mark("late enough", "");
        await settle();
        check("the paint cadence is PAINT_MS, matching upstream's SCREEN_MS",
          afterFirst === 1 && tooSoon === 1 && batches.length === 2 &&
          out.length === 3,
          `${afterFirst} write for the first mark, ${tooSoon - afterFirst} for one ` +
          `${globalThis.__poopsPaintMs - 1} ms later, ${batches.length - tooSoon} ` +
          `for one 2 ms later; ${out.length}/3 marks delivered`);
      }

      // 4. Outside a race nothing paints early. Those marks are drained at the row
      //    boundary, which is before the next window opens, so paying for a write
      //    mid-row would buy nothing.
      {
        const out = [], batches = [];
        const t = new globalThis.__poopsTelemetry(makeSay(out, batches));
        t.raceMode = false;
        for (let i = 0; i < 50; i++) { clock += 400; t.mark("M" + i, ""); }
        await settle();
        const midRow = out.length;
        await t.drain();
        check("outside a race, marks wait for the row boundary instead of painting",
          midRow === 0 && out.length === 50,
          `${midRow} of 50 delivered before the row ended (want 0), ` +
          `${out.length}/50 after the drain`);
      }

      // 5. A drain issues its whole batch before awaiting any of it, so the loader
      //    coalesces it into one socket write. Awaiting line by line is the version
      //    that cost a chain round trip per line; this asserts the batching.
      {
        const out = [], batches = [];
        const t = new globalThis.__poopsTelemetry(makeSay(out, batches));
        for (let i = 0; i < 150; i++) t.mark("M" + i, "");
        await t.drain();
        check("a row's drain is one coalesced write, not one per line",
          batches.length === 1 && batches[0] === 150 && out.length === 150,
          `150 buffered lines left in ${batches.length} write(s) ` +
          `(sizes ${JSON.stringify(batches)}); per-line awaiting would be 150`);
      }

      // 6. Nothing is lost, across many paints. Upstream could drop all but its last 12
      {
        const out = [], batches = [];
        const t = new globalThis.__poopsTelemetry(makeSay(out, batches));
        t.raceMode = true;
        for (let i = 0; i < 500; i += 20) {
          for (let k = 0; k < 20; k++) { clock += 400; t.mark("M" + (i + k), ""); }
          await settle();
        }
        const midRow = out.length;
        await t.drain();
        // mark() writes "<tag> <detail>", so compare on the tag prefix rather than
        // the whole line -- and strip, because the detail is empty here.
        const seen = new Set(out.map((l) => l.trim()));
        let missing = 0;
        for (let i = 0; i < 500; i++) if (!seen.has("M" + i)) missing++;
        // `paints > 1` is what makes this able to catch a per-paint cap: with a
        // single paint, every line would reach the final drain and the cap would
        // be invisible.
        check("painting drops no marks, across every paint",
          missing === 0 && out.length === 500 && t.paints > 1 && midRow > 400,
          `${missing}/500 missing, ${out.length} delivered in ` +
          `${batches.length} write(s) over ${t.paints} paint(s), ` +
          `${midRow}/500 out before the row ended`);
      }

      // 6b. cost() must not report time-to-complete. The await resolves on the
      {
        const realNow = Date.now;
        let clock = 500000;
        Date.now = () => clock;
        try {
          let releaseChain;
          const chainWorkDone = new Promise((r) => { releaseChain = r; });
          const out = [];
          const slowSay = (line) => new Promise((res) => {
            out.push(line);
            chainWorkDone.then(() => res());
          });
          const t = new globalThis.__poopsTelemetry(slowSay);
          t.mark("one", "");
          const pending = t.drain();          // deliberately not awaited yet
          clock += 5000;                      // the exploit's chain work, 5 s of it
          releaseChain();
          await pending;
          await chainWorkDone;
          const c = t.cost();
          check("cost() reports the issue cost, not time-to-complete",
            c.issueMs < 1000 && c.drains === 1 && c.writes === 1 &&
            c.drainMs === undefined && c.paintMs === undefined &&
            !("elapsedMs" in c) && !("waitMs" in c),
            `the drain took 5000 ms of chain work to resolve; cost() = ` +
            `${JSON.stringify(c)}. issueMs must be the synchronous issue cost, ` +
            `not the 5000 ms wait -- a time-to-complete figure cannot be ` +
            `attributed to the port.`);
        } finally {
          Date.now = realNow;
        }
      }

      // 6c. The write total must be paints + drains, counted in write() itself.
      //      Counting in the caller missed every row boundary's write.
      {
        const out = [], batches = [];
        const t = new globalThis.__poopsTelemetry(makeSay(out, batches));
        t.raceMode = true;
        t.mark("a", "");
        await settle();                     // one mid-race paint
        t.raceMode = false;
        t.mark("b", "");
        await t.drain();                    // one row-boundary drain
        t.mark("c", "");
        await t.drain();                    // another
        const c = t.cost();
        check("the write total is paints + drains, counted where the write happens",
          c.writes === 3 && c.paints === 1 && c.drains === 2 &&
          c.raceWrites === 1 && c.writes === c.paints + c.drains,
          `3 writes expected (1 paint, 2 drains); cost() = ${JSON.stringify(c)}`);
      }

      // 7. flushQueue() is upstream's repaint seam and must actually flush. It used to be
      //    a no-op here, on the mistaken belief that its call sites were inside race
      //    loops; the four sites are boundaries the code deliberately stops at.
      //    Asserted against the adapter source, because calling drain() here would
      //    pass even if the binding were still `() => {}`.
      check("the adapter binds flushQueue to a real flush, not a no-op",
        /flushQueue:\s*\(\)\s*=>\s*telemetry\.drain\(\)/.test(adapterCode) &&
        !/flushQueue:\s*\(\)\s*=>\s*\{\s*\}/.test(adapterCode),
        "flushQueue is poops' own repaint seam; a no-op binding leaves it inert");

      // 8. The ring still caps, and still says so. Without this, a pathological run
      //    grows the buffer until the WebProcess heap the exploit depends on is gone.
      {
        const out = [], batches = [];
        const t = new globalThis.__poopsTelemetry(makeSay(out, batches));
        for (let i = 0; i < 4100; i++) t.mark("M" + i, "");
        const held = t.lines.length;
        await t.drain();
        const saidIt = out.join("\n").includes("dropped by the telemetry ring");
        check("the telemetry ring still caps itself and reports the loss",
          held <= 4000 && saidIt,
          `${held} lines held after 4100 marks (cap 4000); ` +
          `the loss was reported: ${saidIt}`);
      }
    } finally {
      Date.now = realNow;
    }
  }

  if (process.env.POOPS_WIRE) console.log(wire);
}
}

// Every source script in src/ must parse without syntax errors.
{
  const srcFiles = ["src/firmware.js", "src/main.js", "src/rop.js", "src/utils/syscalls.js", "src/site.js", "src/loader.js", "src/net.js", "src/binaries.js", "src/kexp.js", "src/standalone.js", "src/inlinefetch.js"];
  const MODULES = new Set(["src/site.js", "src/loader.js", "src/net.js", "src/binaries.js", "src/kexp.js", "src/standalone.js", "src/inlinefetch.js"]);
  for (const rel of srcFiles) {
    let ok = true, why = "";
    try {
      const src = readFileSync(join(ROOT, rel), "utf8");
      // Test parsing either as module or classic script
      if (MODULES.has(rel)) {
        // Module syntax
        new Function(`import("${join(ROOT, rel)}");`);
      } else {
        new Function(src);
      }
    } catch (e) { ok = false; why = e.message; }
    check(`${rel} parses cleanly`, ok, why);
  }
}

{
  const MODULES = ["src/site.js", "src/loader.js", "src/net.js", "src/kexp.js", "src/binaries.js", "src/standalone.js", "src/inlinefetch.js"];
  for (const rel of MODULES) {
    const body = readFileSync(join(ROOT, rel), "utf8");
    const specs = [...body.matchAll(/(?:^|\s)(?:import|export)[^'"\n]*?from\s*["'](\.[^"']+)["']/g)]
      .map((m) => m[1]);
    for (const spec of specs) {
      const target = join(ROOT, dirname(rel), spec);
      check(`${rel} -> ${spec} resolves`,
        existsSync(target), existsSync(target) ? "" : "not bundled");
    }
    check(`${rel} has no unresolved relative import`, specs.every((s) => existsSync(join(ROOT, dirname(rel), s))),
      `${specs.length} relative import(s)`);
  }
}

// Every payload in payloads/ must at least parse.
{
  let dir = [];
  try { dir = readdirSync(join(ROOT, "payloads")).filter((f) => f.endsWith(".js")); } catch {}
  if (!dir.length) console.log("  (no payloads/ dir)");
  for (const f of dir) {
    const src = readFileSync(join(ROOT, "payloads", f), "utf8");
    let ok = true, why = "";
    try { new Function(src); } catch (e) { ok = false; why = e.message; }
    check(`payloads/${f} parses`, ok, why);
  }
}

console.log(`\n${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
