// Offline payload queue checks.

import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import vm from "node:vm";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

const { runPayloadQueue } = await import(pathToFileURL(join(ROOT, "src/standalone.js")).href);
const { createSessionState, createPayloadSession } =
  await import(pathToFileURL(join(ROOT, "src/loader.js")).href);
const { int64 } = await import(pathToFileURL(join(ROOT, "src/utils/int64.js")).href);

let failures = 0;
let checks = 0;
function check(label, ok, detail = "") {
  checks++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${!ok && detail ? "  " + detail : ""}`);
  if (!ok) failures++;
}

//  a console to write to
const lines = [];
globalThis.window = globalThis;
globalThis.fw_str = "9.99";
globalThis.writeLog = (message, type) => {
  lines.push(`${type || "log"}: ${message}`);
};
globalThis.KRW = { firmware: "test", allproc: 0x111 };
globalThis.SYMBOLS = { libkernel: {}, libc: {} };

const text = () => lines.join("\n");
const clear = () => { lines.length = 0; };

//  the same fake the loader's own test uses

function makeFake() {
  const allocs = [];
  let next = 0x20000000;

  function ptr(low, buf, hi = 0) {
    const self = new int64(low, hi);
    self.backing = buf;
    self.add32 = function (off) {
      // Carry into the high word, which the loader relies on: add32 on a real int64
      // is what keeps a base like 0x7ffff8a00000 + 0x1000 at the same address rather
      // than wrapping the low word to zero.
      const total = (hi * 0x100000000) + low + off;
      const moved = new int64(total % 0x100000000, Math.floor(total / 0x100000000));
      moved.backing = buf ? buf.subarray(off) : null;
      moved.add32 = this.add32;
      moved.toString = () => "0x" + ((low + off) >>> 0).toString(16);
      return moved;
    };
    self.toString = () => "0x" + (low >>> 0).toString(16);
    return self;
  }

  const p = {
    malloc(size, type) {
      next += 0x1000;
      const buf = new Uint8Array(Math.max(16, size));
      allocs.push({ start: next, end: next + buf.length });
      return ptr(next, buf);
    },
    write1(a, v) { p._at(a)[0] = v; },
    write2(a, v) { p._at(a, 2, true).setUint16(0, v, true); },
    write4(a, v) { p._at(a, 4, true).setUint32(0, v, true); },
    write8(a, v) { const d = p._at(a, 8, true); d.setUint32(0, v.low, true); d.setUint32(4, v.hi, true); },
    read1(a) { return p._at(a)[0]; },
    read2(a) { return p._at(a, 2, true).getUint16(0, true); },
    read4(a) { return p._at(a, 4, true).getUint32(0, true); },
    read8(a) { const d = p._at(a, 8, true); return new int64(d.getUint32(0, true), d.getUint32(4, true)); },
    leakval: () => ptr(0x30000000, new Uint8Array(16)),
    // Zero high words exercise the xotext range check; separate low words avoid overlap.
    libKernelBase: ptr(0x2a4000),
    libSceNKWebKitBase: ptr(0x400000),
    libSceLibcInternalBase: ptr(0x350000),
    gadgets: new Proxy({}, { get: () => ptr(0x8ffff0000000) }),
    syscalls: new Proxy({}, { get: () => 0 }),
    _at(a, bytes = 1, asView = false) {
      for (const alloc of allocs) {
        if (a.low >= alloc.start && a.low + bytes <= alloc.end) {
          const off = a.low - alloc.start;
          if (!asView) return alloc.buf.subarray(off, off + bytes);
          return new DataView(alloc.buf.buffer, alloc.buf.byteOffset + off, bytes);
        }
      }
      if (!asView) return SCRATCH.subarray(0, bytes);
      return new DataView(SCRATCH.buffer, 0, bytes);
    },
    _allocs: allocs,
  };

  const SCRATCH = new Uint8Array(4096);

  const chain = {
    count: 0,
    stack_entry_point: ptr(0x40000000),
    stack_size: 0x80000,
    reserved_stack: 0x10000,
    initial_count: 3,
    return_value: ptr(0x50000000),
    clear() { this.count = 0; },
    push() { this.count++; },
    push_write8() { this.count += 5; },
    write_result() { this.count += 2; },
    fcall() { this.count += 3; },
    add_syscall() { this.count += 3; },
    add_syscall_ret() { this.count += 5; },
    async run() { this.count = 0; },
    async call() { return new int64(0, 0); },
    async syscall(nr) {
      // getpid-ish: a small nonzero value, so a payload that checks for failure
      // sees success the way it would on hardware.
      return new int64(nr === 0x14 ? 1234 : 0, 0);
    },
    pre_chain() {},
  };

  return { p, chain };
}

console.log("standalone queue runner (protocol + control flow, NOT the ROP chain)\n");

// --- 1. payloads run in order, and each is announced ------------------------
{
  const { p, chain } = makeFake();
  clear();
  const summary = await runPayloadQueue({
    p, chain,
    payloads: [
      { name: "one.js", source: `return async function (api) { await api.log("first"); };`, args: [] },
      { name: "two.js", source: `return async function (api) { await api.log("second"); };`, args: [] },
      { name: "three.js", source: `return async function (api) { await api.log("third"); };`, args: [] },
    ],
  });

  check("all three payloads ran", summary.run === 3 && summary.total === 3,
    `run=${summary.run} failed=${summary.failed}`);
  check("each payload is announced by name and position",
    text().includes("=== [1/3] one.js ===") && text().includes("=== [3/3] three.js ==="));
  check("every payload's log reaches the screen",
    text().includes("first") && text().includes("second") && text().includes("third"));
  check("the runner announces itself as having no socket",
    /standalone runner v[\d.]+: 3 payload\(s\) inline, no socket/.test(text()));
  check("no listening port is claimed", !/9027/.test(text()),
    (text().match(/.*9027.*/) || [""])[0]);
  check("the queue reports its summary",
    text().includes("=== queue finished: 3/3 completed, 0 failed ==="));
  check("the loader's own banners bracket each payload",
    (text().match(/--- payload: \d+ bytes ---/g) || []).length === 3 &&
    (text().match(/--- payload done ---/g) || []).length === 3,
    `${(text().match(/--- payload: \d+ bytes ---/g) || []).length} start banners`);
}

// --- 2. order is strict ----------------------------------------------------
{
  const { p, chain } = makeFake();
  clear();
  // Each payload waits for a timer, and the later one waits longer. If the runner
  // started them concurrently, "two" would land before "one" finished.
  await runPayloadQueue({
    p, chain,
    payloads: [
      { name: "slow.js", source: `return async function (api) {
        await new Promise(r => setTimeout(r, 40));
        await api.log("slow done");
      };` },
      { name: "fast.js", source: `return async function (api) { await api.log("fast done"); };` },
    ],
  });
  const slow = text().indexOf("slow done");
  const fast = text().indexOf("fast done");
  check("a slower payload finishes before the next one starts", slow !== -1 && fast !== -1 && slow < fast,
    `slow at ${slow}, fast at ${fast}`);
}

// --- 3. a throwing payload does not stop the queue -------------------------
{
  const { p, chain } = makeFake();
  clear();
  const summary = await runPayloadQueue({
    p, chain,
    payloads: [
      { name: "boom.js", source: `return async function (api) {
        await api.log("before the throw");
        throw new Error("deliberate failure");
      };` },
      { name: "after.js", source: `return async function (api) { await api.log("still here"); };` },
    ],
  });

  check("the throw is reported", text().includes("deliberate failure"),
    (text().match(/.*deliberate failure.*/) || [""])[0]);
  check("logs before the throw survive", text().includes("before the throw"));
  check("the payload after a throw still runs", text().includes("still here"));
  check("the failure is counted in the summary", summary.failed === 1 && summary.run === 1,
    `run=${summary.run} failed=${summary.failed}`);
}

// Explicit queue stops wait for cleanup and do not run subsequent payloads.
{
  const { p, chain } = makeFake();
  clear();
  const summary = await runPayloadQueue({ p, chain, payloads: [
    { name: "check.js", source: `return async function (api) {
      try { api.stopQueue("already running"); }
      finally { await new Promise(r => setTimeout(r, 5)); await api.log("probe closed"); }
    };` },
    { name: "kernel.js", source: `return async function (api) { await api.log("must not execute"); };` },
  ] });
  check("an explicit stop skips the remaining queue", summary.stopped === true && summary.skipped === 1);
  check("a normal stop is counted as success", summary.run === 1 && summary.failed === 0 && summary.ok);
  check("the payload finishes cleanup before the queue stops",
    text().includes("probe closed") && text().indexOf("probe closed") < text().indexOf("queue stopped"));
  check("the skipped payload is not announced or executed",
    !text().includes("must not execute") && !text().includes("[2/2] kernel.js"));
  check("the stop reason reaches the summary and screen",
    summary.reason === "already running" && text().includes("already running"));
}
{
  const { p, chain } = makeFake();
  clear();
  const summary = await runPayloadQueue({ p, chain, payloads: [
    { name: "failed-check.js", source: `return async function (api) {
      api.stopQueue("probe failed"); throw new Error("unexpected probe error");
    };` },
    { name: "kernel.js", source: `return async function (api) { await api.log("must not execute"); };` },
  ] });
  check("a failure after requesting a stop still skips the queue",
    summary.stopped && summary.failed === 1 && summary.run === 0 && !summary.ok);
  check("failure cannot undo the stop request", !text().includes("must not execute"));
}
{
  const { p, chain } = makeFake();
  clear();
  const summary = await runPayloadQueue({ p, chain, payloads: [
    { name: "first.js", source: `return async function (api) { window.lateQueueStop = api.stopQueue; };` },
    { name: "next.js", source: `return async function (api) {
      if (window.lateQueueStop("stale stop") !== false) throw new Error("stale stop accepted");
      await api.log("next payload ran");
    };` },
  ] });
  check("a completed payload cannot stop the next one", summary.run === 2 && !summary.stopped);
  check("a detached stop after queue completion is refused", window.lateQueueStop("too late") === false);
  delete window.lateQueueStop;
}

// --- 4. a syntax error is reported, and the queue continues -----------------
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [
      { name: "broken.js", source: "return async function (api) { this is not javascript };" },
      { name: "ok.js", source: `return async function (api) { await api.log("recovered"); };` },
    ],
  });
  check("a payload that will not parse is reported, not fatal",
    text().includes("recovered"), (text().match(/.*payload threw.*/) || [""])[0]);
  // A SyntaxError carries no payload.js stack frame -- it failed before any code
  // ran -- so the assertion is on the queue still reporting which payload was
  // running, which is what identifies it on the console.
  check("the parse failure is attributed to the payload that was running",
    text().includes("=== [1/2] broken.js ===") && /payload threw/.test(text()),
    (text().match(/.*payload threw.*/) || ["no throw was reported"])[0]);
  check("the syntax error message survives", /Unexpected identifier|SyntaxError|unexpected/i.test(text()),
    (text().match(/.*payload threw.*/) || [""])[0]);
}

// 5. api.krw carries from one payload to the next.
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [
      { name: "publish.js", source: `return async function (api) {
        api.krw = { tag: "published-by-payload-one" };
        await api.log("krw published");
      };` },
      { name: "consume.js", source: `return async function (api) {
        await api.log("saw krw: " + (api.krw && api.krw.tag));
      };` },
    ],
  });

  check("the second payload sees the first one's api.krw",
    text().includes("saw krw: published-by-payload-one"),
    (text().match(/.*saw krw.*/) || [""])[0]);
  check("the carry-over is announced on screen",
    text().includes("kernel R/W carried into the next payload"));
  check("the final summary reports krw as established", text().includes("krw established"));
}

// --- 6. api.krw starts null in a fresh session -----------------------------
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [{ name: "clean.js", source: `return async function (api) {
      await api.log("krw is " + (api.krw === null ? "null" : "already set"));
    };` }],
  });
  check("a standalone session starts with no krw", text().includes("krw is null"));
}

// --- 7. per-payload args ----------------------------------------------------
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [
      { name: "args.js", args: ["port=1337", "path=/data", "verbose"],
        source: `return async function (api) {
          await api.log("args: [" + api.args.join("|") + "]");
          await api.log("count: " + api.args.length);
        };` },
    ],
  });
  check("args reach the payload in order",
    text().includes("args: [port=1337|path=/data|verbose]"),
    (text().match(/.*args: \[.*/) || [""])[0]);
  check("the arg count matches", text().includes("count: 3"));
  check("args are announced before the payload runs", /args: port=1337 path=\/data verbose/.test(text()));
}

// --- 8. a payload with no args gets an empty array, not undefined ----------
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [{ name: "noargs.js", source: `return async function (api) {
      await api.log("isArray: " + Array.isArray(api.args) + " len: " + api.args.length);
    };` }],
  });
  check("api.args is always an array", text().includes("isArray: true len: 0"));
}

// --- 9. a fresh api per payload: the malloc budget is per payload ----------
//
// MALLOC_LIMIT is 1 MiB per payload, checked against words*4 where p.malloc adds a
// 0x10000-word floor. Two payloads each asking for a little must both succeed; one
// asking for more than the limit must be refused by name.
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [
      { name: "a.js", source: `return async function (api) {
        api.p.malloc(0x1000);
        await api.log("a allocated");
      };` },
      { name: "b.js", source: `return async function (api) {
        api.p.malloc(0x1000);
        await api.log("b allocated");
      };` },
    ],
  });
  check("both payloads can allocate against the same budget",
    text().includes("a allocated") && text().includes("b allocated"),
    (text().match(/.*limited to.*/) || ["no refusal reported"])[0]);
}

{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [
      { name: "greedy.js", source: `return async function (api) { api.p.malloc(0x800000); };` },
      { name: "modest.js", source: `return async function (api) {
        api.p.malloc(0x1000);
        await api.log("modest still allocated");
      };` },
    ],
  });
  check("an over-budget malloc is refused with the limit named",
    text().includes("this payload is limited to 1024 KB"),
    (text().match(/.*limited to.*/) || [""])[0]);
  check("the refusal does not consume the next payload's budget",
    text().includes("modest still allocated"));
}

// --- 10. the xotext read guard is per payload ------------------------------
//
// owned[] is what the guard reads, and it is rebuilt per api. On a shared session it
// would accumulate, and a later payload's read of an earlier payload's buffer would
// be permitted. This checks the refusal still happens for the second payload.
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [
      { name: "keeper.js", source: `return async function (api) {
        api.p.malloc(0x1000);
        await api.log("kept a buffer");
      };` },
      { name: "reader.js", source: `return async function (api) {
        // An address inside libkernel's mapped window: reading it FAULTS on hardware,
        // which is why the loader refuses it before the read happens.
        await api.log("read: " + api.p.read4(api.libKernelBase.add32(0x1000)));
      };` },
    ],
  });
  check("a read of an execute-only library is refused, not attempted",
    text().includes("mapped execute-only"),
    (text().match(/.*execute-only.*/) || ["the read was not refused"])[0]);
  check("the refusal names the address and the library",
    /read4 at 0x[0-9a-f]+ lands inside libkernel/.test(text()),
    (text().match(/.*lands inside.*/) || [""])[0]);
}

// --- 11. setPayloadTimeout, the way a service payload uses it ---------------
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [{ name: "service.js", source: `return async function (api) {
      if (typeof api.setPayloadTimeout !== "function") throw new Error("no setPayloadTimeout");
      api.setPayloadTimeout(0);                       // long-running: no deadline
      await api.log("timeout disabled");
      api.setPayloadTimeout(60000);                   // and back to a real one
      await api.log("timeout reset");
    };` }],
  });
  check("a service payload can disable the deadline", text().includes("timeout disabled"));
  check("a service payload can set a new deadline", text().includes("timeout reset"));
}

{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [{ name: "bad-timeout.js", source: `return async function (api) {
      try { api.setPayloadTimeout(-1); } catch (e) { await api.log("rejected: " + e.message); }
      try { api.setPayloadTimeout(1.5); } catch (e) { await api.log("rejected fractional"); }
      try { api.setPayloadTimeout(2147483648); } catch (e) { await api.log("rejected too large"); }
    };` }],
  });
  check("a negative timeout is rejected", text().includes("rejected: payload timeout must be an integer"));
  check("a fractional timeout is rejected", text().includes("rejected fractional"));
  check("an out-of-range timeout is rejected", text().includes("rejected too large"));
}

// --- 12. sendBlob refuses, and says why ------------------------------------
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [{ name: "sender.js", source: `return async function (api) {
      try { await api.sendBlob(new Uint8Array(32)); }
      catch (e) { await api.log("sendBlob refused: " + e.message); }
    };` }],
  });
  check("sendBlob refuses instead of throwing a TypeError",
    text().includes("sendBlob refused:"), (text().match(/.*sendBlob.*/) || [""])[0]);
  check("the refusal names the byte count", text().includes("api.sendBlob(32 bytes)"));
  check("the refusal points at the remote loader as the alternative",
    text().includes("tools/send.py"));
}

// --- 13. the empty queue is reported, not silently done --------------------
{
  const { p, chain } = makeFake();
  clear();
  const summary = await runPayloadQueue({ p, chain, payloads: [] });
  check("an empty queue is reported", text().includes("empty payload list"),
    (text().match(/.*nothing to run.*/) || [""])[0]);
  check("an empty queue is not reported as success", summary.ok === false);
}

// --- 14. the api is the loader's, not a copy -------------------------------
//
// The point of createPayloadSession() being shared is that a standalone page cannot
// drift from the served one. This compares the two apis' key sets, built by the same
// factory with the same arguments except the log sink and sendBlob.
{
  const { p, chain } = makeFake();
  const state = createSessionState(p, chain);
  const socketish = createPayloadSession({
    p, chain, say: () => {}, state, deadlineControl: { reset: null },
    log: async () => {}, sendBlob: async () => 0, args: [],
    serialise: (fn) => fn(),
  });
  const { runPayloadQueue: _unused } = { runPayloadQueue };
  void _unused;

  // Rebuild the standalone api the way standalone.js does and compare.
  const standaloneApi = createPayloadSession({
    p, chain, say: () => {}, state, deadlineControl: { reset: null },
    log: async () => {}, sendBlob: async () => { throw new Error("no socket"); }, args: [],
  });

  const socketKeys = Object.keys(socketish).sort();
  const standaloneKeys = Object.keys(standaloneApi).sort();
  const missing = socketKeys.filter((k) => !standaloneKeys.includes(k));
  check("the standalone api has every key the socket api has", missing.length === 0,
    `missing: ${missing.join(", ")}`);

  // The properties a payload actually reads, including the ones that are getters.
  for (const key of ["p", "chain", "krw", "version", "fw", "int64", "toI64",
    "isFailure", "describe", "args", "log", "stopQueue", "setPayloadTimeout", "sendBlob",
    "config", "prefetchKexp", "launchKexp", "module"]) {
    check(`api.${key} is present`, key in standaloneApi);
  }
  check("api.chain is the gated chain, not the raw one",
    standaloneApi.chain === state.gatedChain);
  check("api.chain exposes the geometry a batching payload needs",
    typeof standaloneApi.chain.stack_entry_point !== "undefined" &&
    standaloneApi.chain.stack_size === 0x80000 &&
    standaloneApi.chain.reserved_stack === 0x10000 &&
    standaloneApi.chain.initial_count === 3);
  check("api.config names the same binaries the loader does",
    typeof standaloneApi.config.KEXP_BIN === "string" &&
    typeof standaloneApi.config.ELFLDR_ELF === "string",
    JSON.stringify(standaloneApi.config));
  check("api.krwLayout comes from the offsets table", !!standaloneApi.krwLayout);
  let stopError = "";
  try { socketish.stopQueue("no standalone queue"); } catch (error) { stopError = error.message; }
  check("a socket session cannot silently request a standalone stop", /standalone/.test(stopError));
}

// --- 15. the gated chain records rather than executes, until run() ----------
{
  const { p, chain } = makeFake();
  clear();
  await runPayloadQueue({
    p, chain,
    payloads: [{ name: "batch.js", source: `return async function (api) {
      api.chain.clear();
      api.chain.add_syscall(0x14);
      api.chain.add_syscall(0x14);
      const pending = api.chain.count;
      await api.log("pending before run: " + pending);
      await api.chain.run();
      await api.log("pending after run: " + api.chain.count);
    };` }],
  });
  // The count is the number of recorded OPS, not syscalls: clear() records one, so
  // two add_syscalls make three. Asserting 6 would be asserting a different thing.
  check("a batch is recorded, not executed on add",
    text().includes("pending before run: 3"),
    (text().match(/.*pending before run.*/) || [""])[0]);
  check("run() executes the batch and clears it",
    text().includes("pending after run: 0"),
    (text().match(/.*pending after run.*/) || [""])[0]);
}

console.log(`\n${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
