import { readFileSync, existsSync } from "node:fs";

const root = new URL("../", import.meta.url);
const read = (path) => readFileSync(new URL(path, root), "utf8");
const check = (condition, message) => {
  if (!condition) throw new Error(message);
  console.log(`ok: ${message}`);
};

for (const path of [
  "vendor/wobkot/LICENSE.txt",
  "vendor/wobkot/src/misc.js",
  "vendor/wobkot/src/userland.js",
  "vendor/wobkot/src/ps5/impl.js",
  "vendor/wobkot/src/ps5/relapse.js",
  "vendor/wobkot/src/kernel.js",
]) check(existsSync(new URL(path, root)), `vendored ${path}`);

const index = read("index.html");
const order = [
  "src/wobkot_bootstrap.js",
  "vendor/wobkot/src/misc.js",
  "vendor/wobkot/src/ps5/impl.js",
  "vendor/wobkot/src/userland.js",
  "src/wobkot_adapter.js",
  "src/site.js",
].map((path) => index.indexOf(path));
check(order.every((position) => position >= 0), "index loads every Wobkot runtime layer");
check(order.every((position, i) => i === 0 || position > order[i - 1]), "Wobkot scripts load in dependency order");
check(!index.includes("src/webkit.js") && !index.includes("src/rop.js"), "legacy exploit and ROP are not boot scripts");

const host = read("host.py");
check(!host.includes('want_poops =') && !host.includes('candidates.insert(0, "poops.html")'), "host has no Poops router");

const relapse = read("payloads/relapse.js");
check(relapse.includes("window.wobkot.runRelapse()"), "Relapse payload delegates to Wobkot");
check(!relapse.includes("class KernelExploit"), "local Relapse port was removed");

const loader = read("src/loader.js");
check(!loader.includes('import("./lua-vm.js")'), "loader has no Lua runtime dependency");

console.log("Wobkot integration checks passed");
