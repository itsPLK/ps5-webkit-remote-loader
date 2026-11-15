import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) throw new Error("usage: node tools/probe_wobkot_standalone.mjs FILE.html");
const html = readFileSync(file, "utf8");
let failures = 0;
const check = (condition, message) => {
  console.log(`${condition ? "ok  " : "FAIL"} ${message}`);
  if (!condition) failures++;
};
const assignment = (name) => {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = html.match(new RegExp(`^\\s*window\\.${escaped}\\s*=\\s*(.*);\\s*$`, "m"));
  if (!match) return null;
  return JSON.parse(match[1]);
};

const modules = assignment("__modules");
const order = assignment("__order");
const deferred = assignment("__wobkotScripts");
const standalone = assignment("STANDALONE");

check(modules && typeof modules === "object", "module registry is valid JSON");
check(Array.isArray(order) && order.includes("src/site.js"), "module boot order includes site.js");
check(standalone && Array.isArray(standalone.payloads), "standalone payload queue is present");
check(deferred && deferred["vendor/wobkot/src/kernel.js"], "Wobkot kernel is deferred in the page");
check(deferred && deferred["vendor/wobkot/src/ps5/relapse.js"], "Wobkot Relapse is deferred in the page");
check(deferred && deferred["vendor/wobkot/src/kernel.js"].includes("async function kernel_main"), "deferred kernel source is complete");
check(deferred && deferred["vendor/wobkot/src/ps5/relapse.js"].includes("async function exploit_main"), "deferred Relapse source is complete");

for (const marker of [
  "/* === src/wobkot_bootstrap.js === */",
  "/* === vendor/wobkot/src/misc.js === */",
  "/* === vendor/wobkot/src/ps5/impl.js === */",
  "/* === vendor/wobkot/src/userland.js === */",
  "/* === src/wobkot_adapter.js === */",
]) check(html.includes(marker), `${marker.replace(/^\/\* === | === \*\/$/g, "")} is inlined`);

check(!html.includes("rop-slave-source"), "legacy hijacked worker is absent");
check(!html.includes("/* === src/webkit.js === */"), "legacy userland is absent");

for (const [name, source] of Object.entries(modules || {})) {
  try { new Function("__ns", "__req", source); }
  catch (error) { check(false, `${name} parses: ${error.message}`); }
}

if (failures) process.exit(1);
console.log("Wobkot standalone probe passed");
