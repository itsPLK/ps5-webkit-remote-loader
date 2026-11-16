import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("./poops_port/adapter.js.txt", import.meta.url), "utf8");
const workerSource = readFileSync(new URL("../src/main.js", import.meta.url), "utf8");
const payloadSource = readFileSync(new URL("../payloads/poops.js", import.meta.url), "utf8");
const start = source.indexOf("// Wobkot deliberately exposes");
const end = source.indexOf("// Count ROP slots locally");
assert.ok(start >= 0 && end > start, "Poops Wobkot compatibility block is present");
const prepareStart = workerSource.indexOf("async function prepareRop");
const prepareEnd = workerSource.indexOf("// Verify module syscall numbers");
assert.ok(prepareStart >= 0 && prepareEnd > prepareStart);
assert.doesNotMatch(workerSource.slice(prepareStart, prepareEnd), /\bSYS_[A-Z0-9_]+\b/,
  "the Wobkot compatibility initializer has no retired syscall globals");
assert.match(payloadSource,
  /poops port E6:[^\n]*\n\s*const unarmed = needTrigger\("launch the stage 5 payload"\);/,
  "the negative control skips stage 5 instead of reporting a false failure");

const block = source.slice(start, end);
const compile = new Function("load_script", `
  class rop {}
  ${block}
  return { preparePoopsRuntime, usePoopsRuntime, poops_worker_rop };
`);

let loads = 0;
const loaded = async (path) => {
  loads++;
  assert.equal(path, "src/main.js");
};
const compat = compile(loaded);

globalThis.window = { offsetsLoaded: Promise.resolve() };
let prepared = null;
globalThis.prepareRop = async (p, options) => {
  prepared = { p, options };
  return {
    p: {
      gadgets: { ret: 1 },
      syscalls: { 20: 2 },
      libSceNKWebKitBase: "wk",
      libSceLibcInternalBase: "libc",
      libKernelBase: "kernel",
    },
    chain: { stack_entry_point: "worker-stack" },
  };
};

const api = {
  p: { marker: "wobkot-arw" },
  chain: {},
  libSceNKWebKitBase: "api-wk",
  libSceLibcInternalBase: "api-libc",
  libKernelBase: "api-kernel",
  log() {},
};
const runtime = await compat.preparePoopsRuntime(api);
assert.equal(loads, 1, "legacy worker runtime loads once");
assert.equal(prepared.p, api.p, "Wobkot ARW is reused");
assert.equal(prepared.options.WorkerRop, compat.poops_worker_rop);
assert.equal(prepared.options.libKernelBase, "api-kernel");

const payloadApi = compat.usePoopsRuntime(api, runtime);
assert.equal(Object.getPrototypeOf(payloadApi), api, "normal payload API remains the prototype");
assert.equal(payloadApi.p, runtime.p);
assert.equal(payloadApi.chain, runtime.chain);
assert.equal(payloadApi.__poopsDirectChain, runtime.chain);
assert.equal(payloadApi.log, api.log, "normal API methods remain inherited");

const legacyApi = { chain: { stack_entry_point: "already-full" } };
assert.equal(await compat.preparePoopsRuntime(legacyApi), null,
  "an existing full worker chain is left untouched");

console.log("Poops Wobkot compatibility behavior passed");
