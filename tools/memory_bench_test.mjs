import assert from 'node:assert/strict';
import fs from 'node:fs';
const entry = new Function(fs.readFileSync(new URL('../payloads/memory_bench.js', import.meta.url), 'utf8'))();
const memory = new Uint8Array(16384);
const lines = [];
let probes = 0, reads = 0, writes = 0, disabled = false;
const api = {
  args: ['quick'], fw: 'mock',
  setPayloadTimeout: n => { assert.equal(n, 0); disabled = true; },
  log: async line => lines.push(line),
  p: {
    memoryWindowSize: 256,
    malloc: size => { assert.equal(size, 16384); return {low: 4096, hi: 0}; },
    writeBytes: (p, data) => { assert.equal(p.low, 4096); memory.set(data); writes++; },
    readInto: (p, data) => { assert.equal(p.low, 4096); data.set(memory.subarray(0, data.length)); reads++; },
    probeMemoryWindow: (p, size, passes) => { probes++; return passes * Math.ceil(size / 256); },
  },
};
await entry(api);
assert(disabled && probes === 12 && reads > 0 && writes > 0);
assert.equal(lines.filter(l => l.startsWith('samples_ms,')).length, 28);
assert(lines.includes('host benchmark complete; byte checks passed'));
assert(!lines.some(l => /NaN|Infinity/.test(l)));
await assert.rejects(entry({...api, p: {}}), /Reload the updated loader/);
await assert.rejects(entry({...api, p: {...api.p, readInto: (_, data) => data.fill(3)}}), /mismatch/);
console.log('Host memory benchmark tests passed');
