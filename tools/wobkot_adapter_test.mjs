import vm from "node:vm";
import { readFileSync } from "node:fs";

const adapter = readFileSync(new URL("../src/wobkot_adapter.js", import.meta.url), "utf8");
const prelude = `
class BInt {
  constructor(hi = 0, lo) {
    if (lo === undefined) { lo = hi; hi = lo < 0 ? -1 : 0; }
    this.hi = hi >>> 0; this.lo = lo >>> 0;
  }
}
class I64 {
  constructor(low = 0, hi = 0) { this.low = low >>> 0; this.hi = hi >>> 0; }
  add32(n) { return new I64((this.low + n) >>> 0, this.hi); }
  toString() { return this.hi.toString(16) + this.low.toString(16).padStart(8, "0"); }
}
globalThis.int64 = I64;
globalThis.window = globalThis;
globalThis.version = {
  console: 5, major: 3, minor: 0,
  init() {}, toString() { return "3.00"; }
};
let webkit_base = new BInt(0x8, 0x1000);
let libc_base = new BInt(0x8, 0x2000);
let libkernel_base = new BInt(0x8, 0x3000);
const blocks = new Map(); let next = 0x10000;
const mem = { alloc(size) { const at = next; next += 0x1000; blocks.set(at, new ArrayBuffer(size)); return new BInt(0, at); } };
const arw = {
  view(addr) { const block = blocks.get(addr.lo); if (!block) throw new Error("bad address"); return new DataView(block); },
  addrof() { return new BInt(0, 0x4242); }
};
const impl = { wk_RET: new BInt(0x8, 0x4444), wk_POP_RAX_RET: new BInt(0x8, 0x5555) };
function get_syscall(id) { return new BInt(0x8, 0x9000 + id); }
class NativeFunction {
  constructor(target) { this.target = target; }
  invoke(...args) { const id = typeof this.target === "number" ? this.target : this.target.lo; return new BInt(0, id + (args[0] ? args[0].lo : 0)); }
}
async function userland_main() {}
globalThis.notifications = [];
function notify(message) { globalThis.notifications.push(message); }
async function load_script() {
  globalThis.kernel_main = async function () {
    globalThis.kernelRan = true;
    notify("Jailbroken !!");
    notify("another upstream notification");
  };
}
`;

const context = { console, TextEncoder, ArrayBuffer, DataView, Uint8Array, Map, Promise };
vm.createContext(context);
vm.runInContext(prelude + "\n" + adapter, context, { filename: "wobkot-adapter-test.js" });

const runtime = await context.wobkot.initialize();
if (context.fw_str !== "3.00") throw new Error("firmware was not published");
if (runtime.p.libKernelBase.low !== 0x3000) throw new Error("library base translation failed");
const pointer = runtime.p.malloc(16);
runtime.p.write4(pointer, 0xfeedc0de);
if (runtime.p.read4(pointer) !== 0xfeedc0de) throw new Error("memory adapter failed");
const result = await runtime.chain.syscall(20, 7);
if (result.low !== 27) throw new Error("native syscall adapter failed");
await context.wobkot.runRelapse();
if (!context.kernelRan) throw new Error("Relapse boundary did not invoke kernel_main");
if (context.notifications.join("|") !== "another upstream notification")
  throw new Error("the adapter did not suppress only Wobkot's jailbreak notification");
if (context.notify.name !== "notify")
  throw new Error("the upstream notification function was not restored");

console.log("Wobkot adapter behavior passed");
