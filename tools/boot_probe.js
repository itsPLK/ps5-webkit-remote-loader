// Run generated page boot in a VM up to the WebKit exploit.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import vm from "node:vm";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const htmlPath = process.argv[2] ? resolve(process.argv[2]) : join(ROOT, "dist/hello.html");

if (!existsSync(htmlPath)) {
  console.error(
    "boot_probe: HTML file not found: " + htmlPath + "\n" +
    "Build a standalone page first, e.g.:\n" +
    "  python3 tools/build_standalone.py payloads/hello_world.js -o dist/hello.html\n" +
    "Or pass the path to an existing standalone HTML file as an argument."
  );
  process.exit(1);
}

let failures = 0;
let checks = 0;
function check(label, ok, detail = "") {
  checks++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${!ok && detail ? "  " + detail : ""}`);
  if (!ok) failures++;
}

const html = readFileSync(htmlPath, "utf8");

// Every script in document order, with the rop_slave source element excluded -- it
// is DATA (the page turns it into a Blob URL for the Worker), and running it here
// would postMessage() on a global that does not exist.
const blocks = [];
const re = /<script(?<attrs>[^>]*)>(?<body>[\s\S]*?)<\/script>/g;
for (let m = re.exec(html); m; m = re.exec(html)) {
  if (/id="rop-slave-source"/.test(m.groups.attrs)) continue;
  blocks.push({ attrs: m.groups.attrs, body: m.groups.body });
}

// --- the DOM the page actually touches -------------------------------------

const drawn = [];
function makeConsole() {
  return {
    className: "",
    textContent: "",
    style: {},
    childNodes: [],
    appendChild(child) { this.childNodes.push(child); drawn.push(child); return child; },
    removeChild(child) {
      const at = this.childNodes.indexOf(child);
      if (at >= 0) this.childNodes.splice(at, 1);
      return child;
    },
    addEventListener() {},
    setAttribute() {},
    get lastElementChild() { return this.childNodes[this.childNodes.length - 1] || null; },
    scrollTop: 0, scrollHeight: 0,
  };
}

const consoleEl = makeConsole();
const listeners = [];
const errors = [];

const sandbox = {
  console: { log() {}, warn() {}, error() {} },
  TextEncoder, TextDecoder, URL, setTimeout, clearTimeout, queueMicrotask,
  Object, Array, JSON, Math, Number, String, Error, TypeError, RangeError,
  SyntaxError, ReferenceError, Symbol, Boolean, Map, Set, WeakMap, Proxy, Reflect,
  Promise, Uint8Array, Uint32Array, Int32Array, Uint16Array, Float64Array,
  ArrayBuffer, DataView, BigInt, BigInt64Array,
};
sandbox.globalThis = sandbox;
sandbox.window = sandbox;
sandbox.self = sandbox;

// The PS5 User's Guide's WebKit. firmware.js rejects anything else with "PlayStation
// 5 Required", so a desktop agent here would test the rejection path instead of the
// boot path.
sandbox.navigator = { userAgent: "PlayStation 5/9.00" };

sandbox.document = {
  getElementById: (id) => (id === "console" ? consoleEl : makeConsole()),
  createElement: () => makeConsole(),
  // appendChild on an inline <script> is how a browser COMPILES AND RUNS its text.
  // A no-op here would make offsetsInline() appear to succeed while defining nothing,
  // which is the same class of silent failure this probe exists to catch -- so the
  // stub does what the browser does: run the text, in global scope.
  body: { appendChild: appendScript },
  head: { appendChild: appendScript },
  addEventListener(type, fn) { listeners.push({ type, fn }); },
  baseURI: "http://127.0.0.1/document/en/ps5/index.html",
};
sandbox.location = { search: "", hostname: "127.0.0.1" };
sandbox.addEventListener = (type, fn) => listeners.push({ type, fn });
sandbox.alert = (msg) => errors.push(`alert: ${msg}`);

// history.replaceState is what the exploit leans on. Here it is a no-op that records
// the call: enough for the boot to proceed to the point where the exploit needs a
// real WebKit, which is where this probe stops on purpose.
let replaceStateCalls = 0;
sandbox.history = { replaceState() { replaceStateCalls++; } };

// webkit.js refuses outright unless BigInt, MessageChannel, Symbol and
// history.replaceState are all present -- it reports "Unsupported Browser" otherwise.
// MessageChannel is here because the exploit's heap grooming uses
// postMessage(..., [transferable]) to free a 4 MB slab, and because its absence would
// stop the probe before the one thing it is checking.
sandbox.MessageChannel = class MessageChannel {
  constructor() {
    this.port1 = { close() {}, postMessage() {} };
    this.port2 = { close() {}, postMessage() {}, start() {} };
  }
};

// site.js's writeLog() ends every line with these. Present on a real page, absent
// from a bare vm context, and their absence throws out of the very first log call --
// which would make every later assertion in this file fail for a reason that has
// nothing to do with the page.
sandbox.scrollTo = () => {};
sandbox.scrollBy = () => {};

// Blob and Worker: the page builds its ROP worker from a Blob URL. Both are checked
// for existence so the page's own guard runs (and reports its own message) rather
// than this probe having to guess whether Blob URLs work here.
sandbox.Blob = class Blob {
  constructor(parts) { this.parts = parts; this.size = parts.join("").length; }
};
sandbox.URL.createObjectURL = () => "blob:stub/0";
let workersMade = 0;
sandbox.Worker = class Worker {
  constructor(url) { this.url = url; workersMade++; }
  postMessage() {}
  terminate() {}
};

// window.STANDALONE and the embedded data come from the first block, which the page
// itself assigns; nothing to do here.

function appendScript(el) {
  if (typeof el.text === "string" && el.text.length) {
    vm.runInContext(el.text, sandbox, { filename: "inline-script.js" });
  }
  return el;
}

vm.createContext(sandbox);

console.log(`boot probe: ${htmlPath}\n`);


// --- run every block, in order ---------------------------------------------

console.log("script blocks");
check("the page has script blocks", blocks.length > 0, `${blocks.length}`);

let booted = 0;
let firstFailure = null;
for (let i = 0; i < blocks.length; i++) {
  const label = (blocks[i].attrs.match(/id="([^"]+)"/) || [, `block ${i + 1}`])[1];
  try {
    vm.runInContext(blocks[i].body, sandbox, { filename: `${label}.js` });
    booted++;
  } catch (e) {
    firstFailure = { i, label, name: e.name, message: e.message };
    break;
  }
}
check("every script block evaluates", firstFailure === null,
  firstFailure ? `${firstFailure.label}: ${firstFailure.name}: ${firstFailure.message}` : "");

// A customized page waits for its startup scripts before starting the loader.
// Probe that same boundary rather than racing the scripts' async work.
if (sandbox.__startupReady) {
  const ready = await Promise.race([
    sandbox.__startupReady,
    new Promise((resolve) => setTimeout(() => resolve(false), 5000)),
  ]);
  check("startup scripts completed and boot proceeded", ready === true);
}

// --- what the boot sequence installed --------------------------------------

console.log("\nboot sequence");
check("the embedded data is installed", !!sandbox.STANDALONE,
  sandbox.STANDALONE ? "" : "window.STANDALONE was never assigned");
check("the module registry is installed", !!sandbox.__modules);
check("the offsets tables are installed", !!sandbox.__offsets,
  sandbox.__offsets ? `${Object.keys(sandbox.__offsets).length} firmwares` : "absent");
check("the worker factory is installed", typeof sandbox.ropWorkerFactory === "function");
check("the inline offsets loader is installed", typeof sandbox.offsetsInline === "function");
check("the module-graph boot ran", typeof sandbox.__boot === "function");
check("the loader's api factory is reachable",
  typeof sandbox.__namespace === "function");

// The offsets loader runs on demand, and site.js calls it — so by the time the boot
// has reached the exploit, it must have been called for this firmware.
check("the firmware was detected", sandbox.fw_str === "9.00", `fw_str=${sandbox.fw_str}`);

// --- what the page drew ----------------------------------------------------

console.log("\non-screen log");
// Read the text now, not at insertion time: writeLog() fills each div in AFTER
// appending it, so a snapshot taken inside appendChild sees every line as empty.
const logLines = drawn.map((node) => node.textContent);
const text = logLines.join("\n");
check("the page printed its banner", /PS5 WebKit Standalone|PS5 WebKit Remote Loader|PS5 WebKit Loader/.test(text),
  logLines.slice(0, 4).join(" | "));
check("the page printed the user agent", text.includes("PlayStation 5/9.00"));
check("the page printed the firmware", text.includes("9.00"));
check("the exploit was reached", /Starting WebKit exploit/.test(text),
  `last line: ${logLines[logLines.length - 1]}`);
check("a standalone page does not claim to listen on a port", !/9027/.test(text),
  (text.match(/.*9027.*/) || [""])[0]);
check("no alert() fired", errors.length === 0, errors.join("; "));

// Nothing may have thrown out of the boot's own promise chain. site.js attaches a
// .catch that logs, so an error here appears as a drawn line rather than as an
// unhandled rejection -- hence reading the log, not just the exit status.
check("no error was drawn during boot",
  !logLines.some((l) => l.startsWith("- ") || /unhandled|failed to load|no entry point/.test(l)),
  (logLines.filter((l) => l.startsWith("- ")).join(" | ") || ""));

//  let the page's own timers run
await new Promise((resolve) => setTimeout(resolve, 400));
const settle = drawn.map((node) => node.textContent).join("\n");

console.log("\nmodule resolution (main.js's seam)");
check("main.js's module seam is installed", typeof sandbox.moduleLoader === "function");

for (const spec of ["./loader.js", "./net.js", "./socket_test.js"]) {
  let resolved = null;
  let failed = null;
  try {
    resolved = await vm.runInContext(`window.moduleLoader(${JSON.stringify(spec)})`, sandbox);
  } catch (e) {
    failed = e;
  }
  check(`${spec} resolves out of the page`,
    failed === null && resolved && typeof resolved === "object",
    failed ? failed.message : `got ${resolved === null ? "nothing" : typeof resolved}`);
}

// What those modules actually expose. A module that resolves but publishes the wrong
// names is the failure the export comparison in probe_standalone.js cannot see, because
// it never gets to ask the registry for one.
const loaderNs = await vm.runInContext('window.moduleLoader("./loader.js")', sandbox);
check("the resolved loader.js exposes runLoader", typeof loaderNs.runLoader === "function");
const netNs = await vm.runInContext('window.moduleLoader("./net.js")', sandbox);
check("the resolved net.js exposes its CALL table", !!(netNs && netNs.CALL));
const probeNs = await vm.runInContext('window.moduleLoader("./socket_test.js")', sandbox);
check("the resolved socket_test.js exposes runSocketTest",
  typeof probeNs.runSocketTest === "function");

// A specifier nothing embedded must be refused by name, rather than resolving to
// something arbitrary.
let unknownMessage = "";
try {
  await vm.runInContext('window.moduleLoader("./not_a_real_module.js")', sandbox);
} catch (e) {
  unknownMessage = String(e && e.message);
}
check("an unknown module is refused by name", /build_standalone/.test(unknownMessage),
  unknownMessage.slice(0, 80));

console.log("\nafter the page's timers ran");
check("the exploit reached history.replaceState", replaceStateCalls > 0,
  `${replaceStateCalls} call(s)`);
// main.js starts loading the offsets while IT loads -- window.offsetsLoaded is created
// there, and the inline loader resolves it on the next microtask. So by the time the
// exploit is running, the table is already on global scope, which is the intended
// order: the same overlap the served page gets from the <script> tag it appends.
check("the offsets table is on global scope while the exploit runs",
  vm.runInContext("typeof OFFSET_lk__thread_list", sandbox) !== "undefined",
  "main.js loads these while it loads, before the exploit needs them");

// Raced against a deadline anyway. The exploit in this sandbox retries on a timer
// forever, so anything that awaits without a bound here would hang the probe rather
// than fail it -- and a hang reports nothing about the page.
let offsetsError = null;
let offsetsValue = null;
try {
  offsetsValue = await Promise.race([
    vm.runInContext("window.offsetsLoaded", sandbox),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("offsets did not settle within 2s")), 2000)),
  ]);
} catch (e) {
  offsetsError = e;
}
check("window.offsetsLoaded resolves for this firmware", offsetsError === null && offsetsValue === "9.00",
  offsetsError ? offsetsError.message : `resolved ${JSON.stringify(offsetsValue)}`);

check("the offsets main.js reads are all present",
  vm.runInContext(
    "typeof OFFSET_lk__thread_list !== 'undefined' && " +
    "typeof OFFSET_lk_worker_wait_return !== 'undefined' && " +
    "typeof wk_gadgetmap !== 'undefined' && " +
    "typeof syscall_map !== 'undefined'", sandbox) === true,
  "main.js reads these off global scope to find the worker it hijacks");
check("window.KRW and window.SYMBOLS are defined for api.krwLayout and kexp",
  vm.runInContext("!!window.KRW && !!window.SYMBOLS", sandbox) === true);
check("the exploit is progressing rather than stalled before it started",
  /leak_addr|Attempt|Retry|Failed|host_addr/.test(settle) || replaceStateCalls > 0,
  settle.split("\n").slice(-3).join(" | "));


if (process.env.TRACE) {
  console.log("\nTRACE: nodes=" + drawn.length);
  for (const n of drawn) console.log("  " + JSON.stringify(n.textContent));
}
// process.exit rather than letting the loop drain: the exploit retries on a timer
// forever in this sandbox, so without it the process would hang after reporting
// instead of returning a status the caller can branch on.
console.log(`\n${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
