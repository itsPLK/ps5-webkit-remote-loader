import assert from 'node:assert/strict';
import {installWindowP} from '../src/utils/mem.js';
import {int64} from '../src/utils/int64.js';
import {run} from '../src/lua-vm.js';

const base = 0x1234fffffff0;
const storage = new Uint8Array(65568);
let selected = null, selections = 0, resets = 0, failCopy = false, failSelect = false;
let allowed = [0, storage.length];
let bulkWrites = 0, bulkReads = 0, sourceViews = 0;
function index(key) {
  assert(selected !== null, 'access requires selected window');
  if (failCopy) throw Error('copy failed');
  const at = selected + Number(key);
  assert(at >= allowed[0] && at < allowed[1], 'access outside requested range');
  return at;
}
const window = {
  size: 256,
  bytes: new Proxy({}, {
    get: (_, key) => {
      if (key === 'length') { if (selected !== null) bulkReads++; return 256; }
      if (key === 'subarray') throw Error('must not create native window views');
      if (key === 'set') return data => {
        bulkWrites++;
        for (let i = 0; i < data.length; i++) storage[index(i)] = data[i];
      };
      return storage[index(key)];
    },
    set: (_, key, value) => { storage[index(key)] = value; return true; },
  }),
  setAddress(address) {
    assert.equal(selected, null);
    selected = address - base;
    selections++;
    if (failSelect) throw Error('selection failed');
  },
  resetAddress() { selected = null; resets++; },
};
const p = installWindowP(window);
assert.equal(p.memoryWindowSize, 256);
function ptr(offset) {
  const n = base + offset;
  return new int64(n >>> 0, Math.floor(n / 4294967296));
}
for (const offset of [0, 1, 2, 3, 15, 16]) {
  for (const size of [0, 1, 3, 4, 255, 256, 257, 4096, 65536]) {
    allowed = [offset, offset + size];
    storage.fill(0xcc);
    const data = Uint8Array.from({length: size}, (_, i) => (i * 71) & 255);
    data.subarray = function(start, end) {
      assert.equal(selected, null, 'source views must be created before redirecting');
      sourceViews++;
      return Uint8Array.prototype.subarray.call(this, start, end);
    };
    const out = new Uint8Array(size);
    const before = selections;
    p.writeBytes(ptr(offset), data);
    p.readInto(ptr(offset), out);
    assert.deepEqual(out, Uint8Array.from(data));
    assert(storage.subarray(0, offset).every(x => x === 0xcc));
    assert(storage.subarray(offset + size).every(x => x === 0xcc));
    assert.equal(selections - before, 2 * Math.ceil(size / 256));
    assert.equal(selected, null);
    assert.equal(selections, resets);
  }
}
assert(bulkWrites > 0 && bulkReads > 0 && sourceViews > 0);
for (const method of ['readInto', 'writeBytes']) {
  failCopy = true;
  for (const size of [1, 256, 257]) {
    assert.throws(() => p[method](ptr(0), new Uint8Array(size)), /copy failed/);
    assert.equal(selected, null);
  }
  failCopy = false;
  failSelect = true;
  assert.throws(() => p[method](ptr(0), new Uint8Array(1)), /selection failed/);
  assert.equal(selected, null);
  failSelect = false;
  assert.throws(() => p[method](new int64(0xffffffff, 0xffff), new Uint8Array(2)), /canonical/);
  assert.throws(() => p[method](ptr(0), [1, 2]), /typed array/);
}
const probeBefore = selections;
failCopy = true; // The probe must select/reset only, without accessing bytes.
assert.equal(p.probeMemoryWindow(ptr(1), 257, 3), 6);
assert.equal(selections - probeBefore, 6);
assert.equal(selected, null);
failCopy = false;
failSelect = true;
assert.throws(() => p.probeMemoryWindow(ptr(0), 256, 1), /selection failed/);
assert.equal(selected, null);
failSelect = false;
for (const args of [[0,1], [65537,1], [1,0], [1,65537], [1.5,1]])
  assert.throws(() => p.probeMemoryWindow(ptr(0), ...args), /workload/);
assert.throws(() => p.probeMemoryWindow(new int64(0xffffffff, 0xffff), 2, 1), /range/);
// Exercise the shipped Lua bundle against the real bulk primitive; scalar fallback
// is disabled so a missing or incorrect bridge connection cannot pass silently.
allowed = [0, storage.length];
const before = selections;
await run({p: {readInto: p.readInto, writeBytes: p.writeBytes}, int64, args: [], log: async () => {}}, `
  local p = uint64("${base + 1}")
  local data = string.rep("A\\0\\255\\128", 1024)
  memory.write_buffer(p, data)
  local snapshot = memory.read_buffer(p, #data)
  assert(snapshot == data)
  local keyed = {[snapshot] = "original"}
  memory.write_buffer(p, string.rep("x", #data))
  local next_read = memory.read_buffer(p, #data)
  assert(next_read == string.rep("x", #data))
  assert(snapshot == data)
  assert(keyed[data] == "original")
  assert(keyed[next_read] == nil)
  assert(snapshot:sub(1, 4) == "A\\0\\255\\128")
  assert(snapshot .. "!" == data .. "!")
  assert(memory.read_buffer(p, 0) == "")
`);
assert.equal(selections - before, 64);
console.log('Bulk memory window and Lua integration tests passed');
