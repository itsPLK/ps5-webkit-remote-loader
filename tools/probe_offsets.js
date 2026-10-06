// Probe: does the payload's preflight pass on a REAL firmware table?
//
// Loads offsets/7.61.js the way index.html does -- as a CLASSIC script, so its
// top-level `const` declarations land in the global lexical environment -- and
// evaluates the same `typeof NAME` expressions the payload's preflight uses.
// Also prints the globalThis value alongside, because that is the difference
// between the two forms and the reason the guard must use the bare one.
const vm = require("node:vm");
const fs = require("node:fs");

globalThis.window = globalThis; // index.html's window
globalThis.fw_str = "7.61";

const fw = process.argv[2] || "7.61";
vm.runInThisContext(fs.readFileSync(`offsets/${fw}.js`, "utf8"));

const names = [
  "OFFSET_lk_sceKernelGetCurrentCpu",
  "OFFSET_lk_pthread_exit",
  "OFFSET_lk_pthread_create_name_np",
  "OFFSET_lk_pthread_join",
  "OFFSET_lc_longjmp",
];

console.log(`offsets/${fw}.js loaded as a classic script. The payload's guard input:\n`);
let ok = true;
for (const n of names) {
  const bare = vm.runInThisContext(`typeof ${n}`);
  if (bare !== "number") ok = false;
  console.log(`  ${n.padEnd(38)} typeof=${bare.padEnd(10)} globalThis=${String(globalThis[n])}`);
}
console.log(ok
  ? `\n=> the preflight PASSES on fw ${fw}`
  : `\n=> the preflight REFUSES fw ${fw}`);
process.exit(ok ? 0 : 1);