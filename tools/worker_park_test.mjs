import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
// Deterministic tests for park detection and launch ordering: the loader must
// observe the worker at its saved wait fingerprint before arming a chain, and
// refuse to arm onto a worker that never parks.
const source = readFileSync(new URL('../src/main.js',import.meta.url),'utf8');
const settleConstant = source.match(/const ROP_PARK_SETTLE_MS = (\d+);/);
assert(settleConstant, 'worker park settle constant must be included in the fixture');

function makeContext(ropParkMs) {
  const fingerprint = {low: 0x1ac90, hi: 0x8f100000};
  const context = vm.createContext({
    ROP_PARK_MS: ropParkMs,
    ROP_PARK_SETTLE_MS: Number(settleConstant[1]),
    originalReturnAddress: fingerprint,
    returnAddress: {slot: 'slot'},
    Date,
    setTimeout,
    Promise,
    p: {read8: () => context.slotValue},
    slotValue: fingerprint,
  });
  context.fingerprint = fingerprint;
  return context;
}

// Slice the gate functions out of the real source.
const start = source.indexOf('function workerParked()');
const gateStart = source.indexOf('async function waitForPark(what)', start);
const end = source.indexOf('\n  }', gateStart);
assert(start >= 0 && gateStart > start && end > gateStart);
const slice = source.slice(start, end + 4);

function defineGate(context) {
  // Function declarations run in the global scope.
  vm.runInContext(slice, context);
}

// 1. Parked slot: the gate resolves after the configured settle interval.
{
  const context = makeContext(200);
  defineGate(context);
  assert.equal(vm.runInContext('workerParked()', context), true);
  const res = vm.runInContext('(async()=>{await waitForPark("chain launch");return true;})()', context);
  assert.equal(await res, true);
}

// 2. Awake slot: the gate polls the slot until it holds the fingerprint again.
{
  const context = makeContext(200);
  defineGate(context);
  context.slotValue = {low: 0xdeadbeef, hi: 0x8f000000};
  assert.equal(vm.runInContext('workerParked()', context), false);
  context.reads = 0;
  context.p.read8 = () => {
    context.reads++;
    if (context.reads >= 3) context.slotValue = context.fingerprint;
    return context.slotValue;
  };
  const res = vm.runInContext('(async()=>{await waitForPark("detached chain launch");return reads;})()', context);
  const polled = await res;
  assert.ok(polled >= 3, `gate polled ${polled} times, expected at least 3`);
  assert.ok(context.reads >= 3);
}

// 3. Never parks: the gate refuses to arm and throws.
{
  const context = makeContext(10);
  defineGate(context);
  context.slotValue = {low: 0x1234, hi: 0x8f000000};
  const res = vm.runInContext('(async()=>{await waitForPark("chain launch");return "armed";} )()', context);
  await assert.rejects(res, /never returned to its parked slot/);
}

// 4. Ordering: both launch paths gate on the park before reading the stack slot
//    or writing the hook, so a worker that is awake never receives an armed hook.
function indexOfIn(text, from, needle) {
  const i = text.indexOf(needle, from);
  assert(i >= 0, `${needle} missing`);
  return i;
}
const lc = source.indexOf('async function launchChain(chain)');
const lcd = source.indexOf('async function launchChainDetached(chain)');
assert(lc >= 0 && lcd >= 0 && lcd < lc, "launchChainDetached comes before launchChain in main.js");
const lcGate = indexOfIn(source.slice(lc), 0, 'await waitForPark("chain launch");');
const lcStack = indexOfIn(source.slice(lc), 0, 'p.read8(stackPointerSlot)');
assert(lcGate < lcStack, 'launchChain must gate on park before reading the stack slot');
const lcdGate = indexOfIn(source.slice(lcd), 0, 'await waitForPark("detached chain launch");');
const lcdHook = indexOfIn(source.slice(lcd), 0, 'p.write8(returnAddress, gadgets["pop rsp"])');
assert(lcdGate < lcdHook, 'launchChainDetached must gate on park before arming the hook');

// 5. Both detached call sites await the gated launch, so the chain is staged
//    only after the park is observed.
for (const file of ['src/net.js', 'src/socket_test.js']) {
  const src = readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
  assert(/await p\.launch_chain_detached\(chain\)/.test(src), `${file} must await the gated detached launch`);
}

console.log('Worker park gate tests passed');
