// Check generated page structure, module resolution, and embedded assets.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import vm from "node:vm";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const htmlPath = process.argv[2] ? resolve(process.argv[2]) : join(ROOT, "dist/hello.html");

let failures = 0;
let checks = 0;
// `detail` is printed only on failure, for the reason tools/selftest.js gives.
function check(label, ok, detail = "") {
  checks++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${!ok && detail ? "  " + detail : ""}`);
  if (!ok) failures++;
}

// --- take the page apart ---------------------------------------------------

const html = readFileSync(htmlPath, "utf8");

const blocks = [];
const blockRe = /<script(?<attrs>[^>]*)>(?<body>[\s\S]*?)<\/script>/g;
for (let m = blockRe.exec(html); m; m = blockRe.exec(html)) {
  if (/id="rop-slave-source"/.test(m.groups.attrs)) continue;
  blocks.push({ attrs: m.groups.attrs, body: m.groups.body });
}

// The worker source is data in a text/plain element, and it is read by the boot
// script through textContent. It has to be there and it has to be the five lines
// main.js expects, because the whole page depends on having a real thread to
// hijack.
const workerMatch = /<script id="rop-slave-source" type="text\/plain">([\s\S]*?)<\/script>/.exec(html);

function jsonValue(name) {
  const marker = `window.${name} = `;
  const at = html.indexOf(marker);
  if (at === -1) return undefined;
  let i = at + marker.length;

  const skipWs = () => { while (i < html.length && /\s/.test(html[i])) i++; };
  const readString = () => {
    if (html[i] !== '"') throw new Error(`expected a string at offset ${i}`);
    i++;
    let out = "";
    while (i < html.length) {
      const c = html[i];
      if (c === "\\") {
        const next = html[i + 1];
        // The page escapes `<` of a `</` as `<\/`, which JSON treats as a literal
        // `/`. Anything else here is a real escape and goes through JSON.parse so
        // the unicode forms are decoded by something that is not this scanner.
        if (next === "/") { out += "/"; i += 2; continue; }
        if (next === "u") { out += JSON.parse(`"${html.slice(i, i + 6)}"`); i += 6; continue; }
        const two = html.slice(i, i + 2);
        out += JSON.parse(`"${two}"`);
        i += 2;
        continue;
      }
      if (c === '"') { i++; return out; }
      out += c;
      i++;
    }
    throw new Error("unterminated string");
  };

  const readValue = () => {
    skipWs();
    const c = html[i];
    if (c === "{") {
      i++;
      const obj = {};
      skipWs();
      if (html[i] === "}") { i++; return obj; }
      for (;;) {
        skipWs();
        const key = readString();
        skipWs();
        if (html[i] !== ":") throw new Error(`expected ':' at offset ${i}`);
        i++;
        obj[key] = readValue();
        skipWs();
        if (html[i] === ",") { i++; continue; }
        if (html[i] === "}") { i++; return obj; }
        throw new Error(`expected ',' or '}' at offset ${i}`);
      }
    }
    if (c === "[") {
      i++;
      const arr = [];
      skipWs();
      if (html[i] === "]") { i++; return arr; }
      for (;;) {
        arr.push(readValue());
        skipWs();
        if (html[i] === ",") { i++; continue; }
        if (html[i] === "]") { i++; return arr; }
        throw new Error(`expected ',' or ']' at offset ${i}`);
      }
    }
    if (c === '"') return readString();
    const end = i;
    while (i < html.length && !/[,}\]\s;]/.test(html[i])) i++;
    const literal = html.slice(end, i);
    if (literal === "true") return true;
    if (literal === "false") return false;
    if (literal === "null") return null;
    return Number(literal);
  };

  try {
    return readValue();
  } catch (e) {
    return { __parseError: `${name}: ${e.message}` };
  }
}

const modules = jsonValue("__modules") || {};
const order = jsonValue("__order") || [];
const offsets = jsonValue("__offsets") || {};
const standalone = jsonValue("STANDALONE");
const binaries = jsonValue("EMBEDDED_BINARIES");
const binaryInfo = jsonValue("EMBEDDED_BINARY_INFO");

console.log(`single-file page probe: ${htmlPath}\n`);

console.log("structure");
check("the page has script blocks", blocks.length > 0, `${blocks.length}`);
check("the ROP worker source is embedded", !!workerMatch);
check("the worker replies on message", !!workerMatch && /postMessage\(1\)/.test(workerMatch[1]));
check("the module registry is present", Object.keys(modules).length > 0,
  `${Object.keys(modules).length} modules`);
check("the dependency order is present", Array.isArray(order) && order.length > 0,
  `${Array.isArray(order) ? order.length : "not an array"} entries`);
check("the page declares window.STANDALONE", !!standalone && !standalone.__parseError,
  standalone && standalone.__parseError ? standalone.__parseError : "");
check("every classic script is inlined",
  ["src/firmware.js", "src/main.js", "src/rop.js", "src/utils/syscalls.js"]
    .every((rel) => html.includes(`/* === ${rel} === */`)),
  "one of the four classic script blocks is missing");

// --- 1. the flattened module graph ----------------------------------------

console.log("\nmodule exports (the builder's rewrite vs node's own loader)");

// The exports a flattened module publishes are the trailing `__x["name"] = local;`
// assignments the builder appends. Reading them off the source is the honest check:
// it compares the rewrite against the module it rewrote, with no dependence on the
// registry working.
const exportRe = /__x\["([^"]+)"\]\s*=\s*([A-Za-z_$][\w$]*);/g;

// src/site.js is the page's entry point and touches the DOM the moment it is
// imported -- it looks up #console, installs window.writeLog and starts the exploit.
// Stand in the two globals it needs so the module can be loaded here for its export
// list, and nothing more. This is a comparison of names, not a claim that the page
// would run in node, which it would not.
function standInDomGlobals() {
  const element = {
    className: "", textContent: "", childNodes: [], style: {},
    appendChild() { return this; },
    removeChild() { return this; },
    addEventListener() {},
    setAttribute() {},
    get lastElementChild() { return null; },
    get firstChild() { return null; },
    scrollTop: 0, scrollHeight: 0,
  };
  globalThis.document = {
    getElementById: () => element,
    createElement: () => ({ ...element, addEventListener() {} }),
    body: { appendChild() {} },
    addEventListener() {},
    baseURI: "http://127.0.0.1/document/en/ps5/index.html",
  };
  globalThis.window = globalThis;
  // node defines navigator as a getter-only global, so it is replaced rather than
  // assigned. The User-Agent is the real firmware detection input (firmware.js reads
  // it for window.fw_str), which is why it is a PS5 string here and not a desktop
  // one: a non-PS5 agent is what the served page rejects with "PS5 Required".
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: { userAgent: "PlayStation 5/9.00" },
  });
  globalThis.writeLog = () => {};
  // site.js also installs global error handlers and routes window.alert at the
  // console, so that a payload's stray alert() cannot freeze the page.
  globalThis.addEventListener = () => {};
  globalThis.alert = () => {};
  globalThis.fw_str = "9.00";
}
standInDomGlobals();

for (const rel of order) {
  const real = await import(pathToFileURL(join(ROOT, rel)).href);
  const expected = Object.keys(real).filter((k) => k !== "default").sort();

  const source = modules[rel] || "";
  const published = [];
  for (let a = exportRe.exec(source); a; a = exportRe.exec(source)) published.push(a[1]);
  exportRe.lastIndex = 0;
  published.sort();

  const missing = expected.filter((n) => !published.includes(n));
  const extra = published.filter((n) => !expected.includes(n));
  check(`${rel} publishes exactly its exports`,
    missing.length === 0 && extra.length === 0,
    missing.length ? `missing: ${missing.join(", ")}`
      : (extra.length ? `extra: ${extra.join(", ")}` : ""));

  check(`${rel} has no leftover module syntax`,
    !/^\s*(?:import|export)\s/m.test(source),
    (source.match(/^\s*(?:import|export)\s.*$/m) || [""])[0]);
}

// --- 2. the registry runs --------------------------------------------------

console.log("\nmodule registry");
const runtimeBlock = blocks.find((b) => b.body.includes("window.__boot = function"));
check("the runtime block is in the page", !!runtimeBlock);

// Defined here, used by the payload section below as well: a module is asked for the
// way a dependent module asks -- through the registry, not by reading its source.
let ask = () => { throw new Error("the module registry did not boot"); };

// The registry's own context. Declared out here because the offline-fetch section
// below reuses it: installInlineFetch has to be the module the page will call, and it
// installs itself onto a window, so driving it anywhere else would be testing a copy.
let sandbox = null;

if (runtimeBlock) {
  function contextFunction(...args) {
    const body = args.pop();
    return vm.runInContext(`(function anonymous(${args.join(",")}) {\n${body}\n})`,
      sandbox, { filename: "module-from-new-Function.js" });
  }
  contextFunction.prototype = Function.prototype;

  sandbox = {
    console, TextEncoder, TextDecoder, URL, setTimeout, clearTimeout,
    Object, Array, JSON, Math, Number, String, Error, TypeError, RangeError,
    Symbol, Boolean, Map, Set, Proxy, Reflect, Promise,
    Uint8Array, ArrayBuffer, DataView, Set, JSON,
  };
  sandbox.Function = contextFunction;
  sandbox.globalThis = sandbox;
  sandbox.window = sandbox;
  sandbox.self = sandbox;

  // Just enough DOM for the entry module. site.js reaches for #console while it
  // evaluates and calls run() as a side effect, so without these the boot stops on
  // `getElementById` -- which would say nothing about the module graph this section
  // exists to check.
  const consoleEl = {
    className: "", textContent: "", childNodes: [], style: {},
    appendChild(c) { this.childNodes.push(c); return c; },
    removeChild() { return null; },
    addEventListener() {}, setAttribute() {},
    get lastElementChild() { return this.childNodes[this.childNodes.length - 1] || null; },
    scrollTop: 0, scrollHeight: 0,
  };
  sandbox.document = {
    getElementById: () => consoleEl,
    createElement: () => ({ ...consoleEl, addEventListener() {} }),
    body: { appendChild() {} },
    addEventListener() {},
    baseURI: "http://127.0.0.1/document/en/ps5/index.html",
  };
  sandbox.location = { search: "" };
  sandbox.navigator = { userAgent: "PlayStation 5/9.00" };
  sandbox.history = { replaceState() {} };
  sandbox.addEventListener = () => {};
  sandbox.alert = () => {};
  sandbox.fw_str = "9.00";
  sandbox.KRW = { firmware: "test", allproc: 0x111 };
  sandbox.SYMBOLS = { libkernel: {}, libc: {} };

  vm.createContext(sandbox);

  let booted = null;
  try {
    vm.runInContext(runtimeBlock.body, sandbox, { filename: "runtime.js" });
    sandbox.window.__modules = modules;
    sandbox.window.__order = order;
    sandbox.window.__boot();
  } catch (e) {
    booted = e;
  }
  check("every module in the graph evaluates", !booted,
    booted ? `${booted.name}: ${booted.message}` : "");
  check("the boot entry point is a function", typeof sandbox.window.__boot === "function");

  ask = (rel) => vm.runInContext(`__namespace(${JSON.stringify(rel)})`, sandbox);

  const standaloneModule = ask("src/standalone.js");
  check("src/standalone.js is reachable from the registry", !!standaloneModule);
  check("runPayloadQueue is the registry's entry point",
    standaloneModule && typeof standaloneModule.runPayloadQueue === "function",
    standaloneModule ? Object.keys(standaloneModule).join(", ") : "module missing");

  const loaderModule = ask("src/loader.js");
  check("createPayloadSession is reachable", loaderModule
    && typeof loaderModule.createPayloadSession === "function");
  check("executePayload is reachable", loaderModule
    && typeof loaderModule.executePayload === "function");
  check("createSessionState is reachable", loaderModule
    && typeof loaderModule.createSessionState === "function");

  const kexpModule = ask("src/kexp.js");
  check("kexp's runKexp is reachable", kexpModule && typeof kexpModule.runKexp === "function");

  const webkit = ask("src/webkit.js");
  check("establishPrimitive is reachable", webkit && typeof webkit.establishPrimitive === "function");

  const netModule = ask("src/net.js");
  check("net's CALL table is reachable", netModule && !!netModule.CALL);

  // Last, because it is the module that imports every other one.
  const site = ask("src/site.js");
  check("src/site.js is reachable from the registry", !!site && typeof site === "object");

  const inline = ask("src/inlinefetch.js");
  check("installInlineFetch is reachable", inline
    && typeof inline.installInlineFetch === "function");
}

//  2b. the offline fetch
if (binaries && runtimeBlock) {
  console.log("\noffline fetch");

  // The registry's own context, so installInlineFetch is the module the page will
  // actually call rather than a copy of it. Its fetch is a stub that always refuses,
  // which is what makes the last assertion below meaningful: anything the inline fetch
  // answers, it answered itself.
  vm.runInContext(
    'window.fetch = function () { return Promise.reject(new Error("the network is not reachable")); };',
    sandbox);

  const installed = vm.runInContext(`(function (binaries) {
    return __namespace("src/inlinefetch.js").installInlineFetch(binaries);
  })(${JSON.stringify(binaries)})`, sandbox);

  check("installInlineFetch reports the paths it took",
    installed.length === Object.keys(binaries).length,
    `${installed.length} of ${Object.keys(binaries).length}`);

  for (const path of Object.keys(binaries)) {
    // Fetched the way kexp.js fetches: by the same repo-relative path, resolved
    // against a document URL, which is what produces the prefixed absolute URL the
    // suffix match has to cope with.
    const documentUrl = "http://127.0.0.1/document/en/ps5/index.html";
    const absolute = new URL(path, documentUrl).href;
    let response = null;
    let fetchError = null;
    try {
      response = await vm.runInContext(
        `window.fetch(${JSON.stringify(absolute)})`, sandbox);
    } catch (e) {
      fetchError = e;
    }
    check(`${path} is served by the inline fetch`, !!response && !fetchError,
      fetchError ? fetchError.message : "no response");

    if (response) {
      const buffer = await response.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      // External assets and overrides need not exist under the repository URL.
      const info = binaryInfo && binaryInfo[path];
      if (info) {
        check(`${path} comes back the right length`, bytes.length === info.size);
        check(`${path} matches its input digest`,
          createHash("sha256").update(bytes).digest("hex") === info.sha256);
      } else {
        const onDisk = readFileSync(join(ROOT, path));
        check(`${path} comes back the right length`, bytes.length === onDisk.length);
        check(`${path} comes back byte-identical`, Buffer.from(bytes).equals(onDisk));
      }
      check(`${path} reports ok and 200, so kexp.js's checks proceed`,
        response.ok === true && response.status === 200);
    }
  }

  // An unembedded URL must still reach the network, so a payload that legitimately
  // fetches something is not silently handed an empty body.
  let passthrough = null;
  try {
    await vm.runInContext(`window.fetch("https://example.invalid/x.js")`, sandbox);
  } catch (e) {
    passthrough = e.message;
  }
  check("an unembedded URL goes to the real network, not a stub",
    passthrough !== null && /not reachable/.test(passthrough),
    passthrough === null ? "the inline fetch answered it" : passthrough);
}

// --- 3. offsets ------------------------------------------------------------

console.log("\noffsets");

// A document stub whose appendChild compiles and runs the element's text as a
  // classic script in this context's global scope -- which is what a browser does
  // with an inline <script>, and what the page's offsetsInline() relies on.
  const offsetSandbox = { console, Object, Array, Math, Number, String, Boolean };
  offsetSandbox.window = offsetSandbox;
  offsetSandbox.globalThis = offsetSandbox;
  offsetSandbox.self = offsetSandbox;
  offsetSandbox.document = {
    head: {
      appendChild(el) {
        // A fresh Function would be wrong here, and the whole reason this check
        // exists: a top-level const in a classic script lands in the global lexical
        // environment, while const in eval'd or Function'd code is scoped to that
        // call and is gone when it returns. vm.runInContext is a script, not an eval.
        vm.runInContext(el.text, offsetSandbox, { filename: el.__name });
      },
    },
    createElement: () => ({ text: "", __name: "offsets/7.61.js" }),
  };
  vm.createContext(offsetSandbox);

  // Loaded the way the page loads it: as a script element, not through eval.
  let offsetError = null;
  try {
    const el = offsetSandbox.document.createElement("script");
    el.text = offsets["7.61"];
    offsetSandbox.document.head.appendChild(el);
  } catch (e) {
    offsetError = e;
  }
  check("the 7.61 table evaluates as a script element", !offsetError,
    offsetError ? `${offsetError.name}: ${offsetError.message}` : "");

// Exactly the names main.js, rop.js and kexp.js read off global scope afterwards,
// and exactly the list the generated page checks for. Duplicated here on purpose:
// the probe is a second, independent reader of the same requirement, and a single
// shared list would let an edit that breaks both hide from both.
const REQUIRED_OFFSET_GLOBALS = [
  "OFFSET_wk_host_constructor_candidates", "OFFSET_wk_memset_import",
  "OFFSET_wk___stack_chk_guard_import", "OFFSET_lk__thread_list",
  "OFFSET_lk_worker_wait_return", "OFFSET_lk___stack_chk_guard",
  "OFFSET_lc_memset", "OFFSET_lc_setjmp", "OFFSET_lc_longjmp",
  "wk_gadgetmap", "syscall_map",
];

// Asked as bare identifiers inside the context, not as properties of the sandbox
// object. A top-level const in a classic script lands in the global LEXICAL
// environment rather than as a property of the global object, so the sandbox's own
// properties never include them even on a table that worked perfectly -- which is
// exactly why the generated page's check is written the same way.
for (const name of REQUIRED_OFFSET_GLOBALS) {
  check(`${name} is readable afterwards`,
    vm.runInContext(`typeof ${name}`, offsetSandbox) !== "undefined");
}
check("window.KRW is defined", !!offsetSandbox.window.KRW);
check("window.SYMBOLS is defined", !!offsetSandbox.window.SYMBOLS);
check("every firmware's table is embedded", Object.keys(offsets).length >= 33,
  `${Object.keys(offsets).length} firmwares`);

// Every table, not just 7.61: the page picks by User-Agent at runtime, and this is
// built on a PC that does not know which console will open it. A table that does not
// evaluate is a console that boots to a SyntaxError naming a line inside a string,
// with nothing in the log to connect it to the firmware it was trying to load.
const badTables = [];
for (const [fw, source] of Object.entries(offsets)) {
  const ctx = { console, Object, Array, Math, Number, String, Boolean };
  ctx.window = ctx;
  ctx.globalThis = ctx;
  ctx.self = ctx;
  ctx.document = {
    head: { appendChild(el) { vm.runInContext(el.text, ctx, { filename: `offsets/${fw}.js` }); } },
    createElement: () => ({ text: "" }),
  };
  vm.createContext(ctx);
  try {
    const el = ctx.document.createElement("script");
    el.text = source;
    ctx.document.head.appendChild(el);
  } catch (e) {
    badTables.push(`${fw} (${e.message})`);
  }
  // And it must define what the loader reads. A table that runs but lands nothing is
  // the failure the page's own offsetsInline() reports by name.
  for (const name of REQUIRED_OFFSET_GLOBALS) {
    if (vm.runInContext(`typeof ${name}`, ctx) === "undefined") {
      badTables.push(`${fw} does not define ${name}`);
    }
  }
}
check("every embedded offsets table evaluates and defines what the loader reads",
  badTables.length === 0, badTables.slice(0, 3).join("; "));

// --- 4. payloads -----------------------------------------------------------

console.log("\npayloads");
const queue = (standalone && standalone.payloads) || [];
check("the queue is not empty", queue.length > 0, `${queue.length} entries`);

let int64Ctor = null;
function askInt64() {
  if (!int64Ctor) int64Ctor = ask("src/utils/int64.js").int64;
  return int64Ctor;
}

function fakeRuntime() {
  const buffers = new Map();
  let next = 0x20000000;
  const Int64Proto = askInt64().prototype;

  const ptr = (low, buf) => {
    const self = Object.create(Int64Proto);
    self.low = low >>> 0;
    self.hi = 0;
    self.backing = buf || null;
    self.add32 = function (off) {
      const moved = Object.create(Int64Proto);
      moved.low = (low + off) >>> 0;
      moved.hi = 0;
      moved.backing = buf ? buf.subarray(off) : null;
      moved.add32 = this.add32;
      return moved;
    };
    return self;
  };

  const SCRATCH = new Uint8Array(4096);
  const at = (a, bytes = 1) => {
    const buf = buffers.get(a.low);
    return (buf || SCRATCH).subarray(0, bytes);
  };
  const view = (a, bytes) => {
    const buf = buffers.get(a.low) || SCRATCH;
    return new DataView(buf.buffer, buf.byteOffset, bytes);
  };

  const p = {
    malloc(size) {
      next += 0x1000;
      const buf = new Uint8Array(Math.max(16, size));
      buffers.set(next, buf);
      return ptr(next, buf);
    },
    write1(a, v) { at(a)[0] = v; },
    write2(a, v) { view(a, 2).setUint16(0, v, true); },
    write4(a, v) { view(a, 4).setUint32(0, v, true); },
    write8(a, v) { const d = view(a, 8); d.setUint32(0, v.low, true); d.setUint32(4, v.hi, true); },
    read1(a) { return at(a)[0]; },
    read2(a) { return view(a, 2).getUint16(0, true); },
    read4(a) { return view(a, 4).getUint32(0, true); },
    read8(a) { const d = view(a, 8); return askInt64()(d.getUint32(0, true), d.getUint32(4, true)); },
    leakval: () => ptr(0x30000000, new Uint8Array(16)),
    // Library bases with a zero high word and well-separated low words: the loader's
    // xotext guard skips any address whose high word is set, and two libraries sharing
    // a low word would land inside each other's window.
    libKernelBase: ptr(0x2a4000),
    libSceNKWebKitBase: ptr(0x400000),
    libSceLibcInternalBase: ptr(0x350000),
    gadgets: new Proxy({}, { get: () => ptr(0x410000) }),
    syscalls: new Proxy({}, { get: () => 0 }),
  };

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
    async call() { return askInt64()(0, 0); },
    async syscall() { return askInt64()(1234, 0); },
    pre_chain() {},
  };

  return { p, chain };
}

for (const entry of queue) {
  check(`${entry.name} is a non-empty string`, typeof entry.source === "string" && entry.source.length > 0,
    `${typeof entry.source} / ${entry.source && entry.source.length}`);
  check(`${entry.name} has an args array`, Array.isArray(entry.args));
  check(`${entry.name} round-trips through JSON`,
    JSON.parse(JSON.stringify(entry.source)) === entry.source);

  // The same wrapper the loader uses, with the same sourceURL, so a payload that
  // throws on a bad line would report the same payload.js:LINE the console does.
  let threw = null;
  let returned = null;
  try {
    const { p, chain } = fakeRuntime();
    const loaderModule = ask("src/loader.js");
    const state = loaderModule.createSessionState(p, chain);
    const api = loaderModule.createPayloadSession({
      p, chain, say: () => {}, state, deadlineControl: { reset: null },
      log: async () => {}, sendBlob: async () => 0, args: entry.args,
    });
    const payloadGlobal = {
      console, TextEncoder, TextDecoder, Proxy, Object, Array, Math, Number, String,
      Error, Uint8Array, ArrayBuffer, DataView, Date, JSON, Promise, Map, Set,
      int64: askInt64(),
    };
    const runner = vm.runInNewContext(
      `(async function () {\n${entry.source}\n//# sourceURL=payload.js\n})`,
      payloadGlobal,
      { filename: "payload.js" });
    returned = await runner();
  } catch (e) {
    threw = e;
  }
  check(`${entry.name} compiles and passes its own capability checks`,
    typeof returned === "function",
    threw ? `${threw.name}: ${threw.message}` : `got ${typeof returned}`);
}

// --- 5. embedded binaries --------------------------------------------------

console.log("\nembedded binaries");
if (binaries) {
  const config = ask("src/binaries.js").DEFAULT_BINARIES;
  for (const [path, b64] of Object.entries(binaries)) {
    check(`${path} is embedded`, typeof b64 === "string" && b64.length > 0);
    // Decoded with the page's own algorithm, transcribed from the generated runtime,
    // so a bug in that decoder fails here and not on hardware.
    const bytes = pageStyleBase64(b64);

    // The same checks src/kexp.js makes on these two files, in the same order and
    // with the same thresholds -- because those checks are what will run on the
    // console, and a decoder that drops one byte changes what they conclude.
    // kexp.js tests the ELF magic only for elfldr; for the shellcode it only checks
    // a minimum size, because the shellcode is not an ELF.
    if (path === config.ELFLDR_ELF) {
      check(`${path} decodes to the ELF magic kexp.js requires`,
        bytes.length >= 0x1000 && bytes[0] === 0x7f && bytes[1] === 0x45 &&
        bytes[2] === 0x4c && bytes[3] === 0x46,
        `${bytes.length} bytes, magic ${[...bytes.slice(0, 4)].map((b) => b.toString(16)).join(" ")}`);
    } else if (path === config.KEXP_BIN) {
      check(`${path} decodes past kexp.js's minimum shellcode size`,
        bytes.length >= 0x400, `${bytes.length} bytes, needs >= ${0x400}`);
    }

    const info = binaryInfo && binaryInfo[path];
    if (info) {
      check(`${path} matches its input size and digest`,
        bytes.length === info.size &&
        createHash("sha256").update(bytes).digest("hex") === info.sha256);
    } else {
      const onDisk = readFileSync(join(ROOT, path));
      check(`${path} matches the file on disk`, Buffer.from(bytes).equals(onDisk));
    }
  }
} else {
  check("no binaries embedded (--no-kexp)", true);
}

// The decoder from the generated page's OFFLINE_JS, written the same way here on
// purpose: two independent transcriptions of the same algorithm agreeing is a
// stronger signal than one of them agreeing with itself.
function pageStyleBase64(b64) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const lookup = {};
  for (let i = 0; i < alphabet.length; i++) lookup[alphabet.charAt(i)] = i;
  const clean = String(b64).replace(/[\s=]+$/g, "");
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let at = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = lookup[clean.charAt(i)];
    const c1 = lookup[clean.charAt(i + 1)];
    const c2 = lookup[clean.charAt(i + 2)];
    const c3 = lookup[clean.charAt(i + 3)];
    if (c0 === undefined || c1 === undefined) {
      throw new Error("corrupt base64 at " + i);
    }
    let bits = (c0 << 18) | (c1 << 12);
    out[at++] = (bits >> 16) & 0xff;
    if (c2 !== undefined) {
      bits |= c2 << 6;
      out[at++] = (bits >> 8) & 0xff;
      if (c3 !== undefined) {
        bits |= c3;
        out[at++] = bits & 0xff;
      }
    }
  }
  return out.subarray(0, at);
}

console.log(`\n${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
