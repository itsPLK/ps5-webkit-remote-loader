import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const source = readFileSync(new URL('../src/main.js', import.meta.url), 'utf8');
const profileStart = source.indexOf('  // Opt-in, scoped counters.');
const launchStart = source.indexOf('  async function launchChain(chain) {', profileStart);
const runtimeStart = source.indexOf('  const runtime = {', launchStart);
assert(profileStart >= 0 && launchStart > profileStart && runtimeStart > launchStart);
const profileSource = source.slice(profileStart, launchStart);
const launchSource = source.slice(launchStart, runtimeStart);
function fixture(mode = 'complete') {
  const context = vm.createContext({
    clock: 0,
    performance: {now() { context.clock += 0.25; return context.clock; }},
    worker: {postMessage() {
      if (mode === 'complete') setTimeout(() => context.worker.onmessage(), 0);
    }},
    ROP_WAIT_MS: 50,
    OFFSET_lc_longjmp: 16,
    setTimeout, clearTimeout,
    waitForPark: async () => { context.clock += 3; },
    originalContext: {add32: n => ({low:n, hi:0})},
    returnAddress: {add32: n => ({low:n, hi:0})},
    stackPointerSlot: {low:8, hi:0},
    originalReturnAddress: {low:9, hi:0},
    gadgets: {'pop rsp': {low:10, hi:0}},
    libSceLibcInternalBase: {add32: n => ({low:n, hi:0})},
    restoreCount: 0,
    p: {
      read8() { context.clock += 0.5; return {low:11, hi:0}; },
      write8() { context.clock += 0.5; },
    },
  });
  context.restoreHook = () => { context.restoreCount++; };
  vm.runInContext(profileSource + '\n' + launchSource, context);
  context.chain = {
    stack_entry_point: {low:12, hi:0},
    push_write8() { context.clock += 0.5; },
    push() { context.clock += 0.5; },
  };
  return context;
}
{
  const c = fixture();
  const measured = await vm.runInContext(`(async()=>{
    const result = await measureWorkerCalls(async()=>launchChain(chain));
    return result;
  })()`, c);
  assert.equal(measured.timing.calls, 1);
  assert.equal(measured.timing.completed, 1);
  assert.equal(measured.timing.parkFailures, 0);
  assert.equal(measured.timing.timeouts, 0);
  assert(measured.timing.parkMs >= 3);
  assert(measured.timing.setupMs > 0);
  assert(measured.timing.completionMs > 0);
  assert.equal(c.restoreCount, 1);
  assert.equal(vm.runInContext('workerTiming === null', c), true);
}
{
  const c = fixture('timeout');
  c.waitForPark = async () => { c.clock += 2; };
  await assert.rejects(vm.runInContext('(async()=>measureWorkerCalls(()=>launchChain(chain)))()', c),
    /never answered/);
  assert.equal(c.restoreCount, 1);
  assert.equal(vm.runInContext('workerTiming === null', c), true);
}
{
  const c = fixture();
  c.waitForPark = async () => { c.clock += 2; throw Error('park failed'); };
  await assert.rejects(vm.runInContext('(async()=>measureWorkerCalls(()=>launchChain(chain)))()', c), /park failed/);
  assert.equal(vm.runInContext('workerTiming === null', c), true);
}
{
  const c = fixture();
  await assert.rejects(vm.runInContext(`(async()=>measureWorkerCalls(async()=>{
    await measureWorkerCalls(async()=>{});
  }))()`, c), /already active/);
  assert.equal(vm.runInContext('workerTiming === null', c), true);
}
console.log('Worker phase timing tests passed');
