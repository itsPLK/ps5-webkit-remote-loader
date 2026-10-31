import assert from 'node:assert/strict';
import fs from 'node:fs';
import {int64} from '../src/utils/int64.js';
const entry = new Function(fs.readFileSync(new URL('../payloads/syscall_bench.js', import.meta.url), 'utf8'))();
async function exercise(corrupt = false) {
  const lines = [], memory = new Map();
  let ops = [], launches = 0, saved = 0, clears = 0, workerCalls = 0;
  const api = {
    args: ['quick'], fw: 'mock', int64,
    log: async text => lines.push(text),
    p: {
      malloc: (size, type) => { assert.equal(size, 256); assert.equal(type, 1); return new int64(4096); },
      write8: (ptr, value) => memory.set(ptr.low, value),
      read8: ptr => memory.get(ptr.low),
      measureWorkerCalls: async fn => {
        const before = workerCalls;
        const result = await fn();
        const calls = workerCalls - before;
        return {result, timing: {calls, completed: calls, parkFailures: 0, timeouts: 0,
          clockErrors: 0, parkMs: calls * 0.5, setupMs: calls * 0.1, completionMs: calls * 1.0}};
      },
    },
    chain: {
      syscall: async n => { assert.equal(n, 20); assert.equal(ops.length, 0); launches++; workerCalls++; return new int64(77); },
      clear: () => { clears++; ops.push(['clear']); },
      add_syscall_ret: (ptr, n) => { assert.equal(n, 20); ops.push(['getpid', ptr]); },
      run: async () => {
        assert(ops.some(op => op[0] === 'getpid'), 'must execute a real syscall');
        launches++;
        workerCalls += ops.filter(op => op[0] === 'getpid').length;
        for (const [kind, ptr] of ops) if (kind === 'getpid') {
          memory.set(ptr.low, new int64(corrupt ? 78 : 77)); saved++;
        }
        ops = [];
      },
    },
  };
  await entry(api);
  assert.equal(ops.length, 0);
  assert.equal(launches, 51); // Includes profiled individual and batch-32 samples.
  assert.equal(saved, 620); // Includes two profiled batches of 32.
  assert.equal(clears, 18);
  assert.equal(lines.filter(l => l.startsWith('samples_ms,')).length, 21);
  assert.equal(lines.filter(l => l.startsWith('worker_phase_samples_ms,')).length, 2);
  assert.equal(lines.filter(l => l.startsWith('instrumentation_overhead_ms,')).length, 2);
  assert(lines.includes('host syscall benchmark complete; all saved results verified'));
  assert(!lines.some(l => /NaN|Infinity/.test(l)));
}
await exercise();
await assert.rejects(exercise(true), /result mismatch/);
await assert.rejects(entry({chain: {}}), /Gated batch API/);
console.log('Host syscall benchmark tests passed');
