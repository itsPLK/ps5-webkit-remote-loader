const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Evaluate the actual shipped payload without Node globals, Wasm, or a DOM.
const code = fs.readFileSync(path.resolve(__dirname, '../../payloads/lua_loader.js'), 'utf8');
const context = vm.createContext({ TextDecoder, TextEncoder, WebAssembly: undefined });
const entry = vm.runInContext('(function () {\n' + code + '\n})()', context);
async function run(source) {
  const lines = [];
  let active = false;
  await entry({ args: source === undefined ? [] : [source], log: async line => {
    assert.equal(active, false, 'logs must be awaited');
    active = true;
    await Promise.resolve();
    lines.push(line);
    active = false;
  } });
  return lines;
}
(async () => {
  assert.deepEqual(await run(), ['2']);
  assert.deepEqual(await run('print("hello", true, nil); print("zażółć 🌙")'),
    ['hello\ttrue\tnil', 'zażółć 🌙']);
  assert.deepEqual(await run('print(string.byte("a\\0b", 2)); print(6 * 7)'), ['0', '42']);
  assert.deepEqual(await run('print(setmetatable({}, {__tostring=function() return "custom" end}))'), ['custom']);
  await run('shared_value = 42');
  assert.deepEqual(await run('print(shared_value)'), ['nil']);
  await assert.rejects(run('local ='), /payload.lua/);
  await assert.rejects(run('error("boom")'), /boom/);
  await assert.rejects(run('error({})'), /non-string error/);
  await assert.rejects(run('while true do end'), /instruction budget/);
  await assert.rejects(run('print(string.rep("x", 1048577))'), /output budget/);
  const lines = [];
  await assert.rejects(entry({ args: ['print("before"); error("after")'],
    log: async line => lines.push(line) }), /after/);
  assert.deepEqual(lines, ['before']);
  await assert.rejects(entry({ args: [], log: async () => { throw Error('log failed'); } }), /log failed/);
  assert.deepEqual(await run(), ['2']);
  const calls = [], nativeLines = [];
  function Int64(low, hi) { this.low = low; this.hi = hi; }
  let inFlight = false;
  const nativeApi = {
    int64: Int64, args: [], log: async line => nativeLines.push(line),
    chain: {
      syscall: async (number, ...args) => {
        assert.equal(inFlight, false);
        inFlight = true;
        await Promise.resolve();
        calls.push([number, ...args]);
        inFlight = false;
        if (number === 999) throw Error('native failure');
        return new Int64(0x89abcdef, 0xfedcba98);
      },
      call: async (target, ...args) => {
        calls.push([target, ...args]);
        return new Int64(7, 0);
      },
    },
  };
  async function nativeRun(source) { await entry({...nativeApi, args:[source]}); }
  await nativeRun(`
    assert(tostring(uint64("0xffffffffffffffff") + 1) == "0x0")
    assert(tostring(uint64(0) - 1) == "0xffffffffffffffff")
    assert(tostring(uint64("0x100000001") * uint64("0x100000001")) == "0x200000001")
    assert(tostring(uint64(1) << 63) == "0x8000000000000000")
    assert(tostring(uint64("0x8000000000000000") >> 63) == "0x1")
    assert(tostring(uint64(1) << 64) == "0x0")
    assert(uint64(1) < uint64(2) and uint64(2) <= uint64(2))
    assert(uint64("0xffffffffffffffff") == uint64(-1))
    assert(tostring(uint64(15) & uint64(3)) == "0x3")
    assert(tostring(uint64(1) | uint64(2)) == "0x3")
    assert(tostring(uint64(3) ~ uint64(1)) == "0x2")
    print(syscall.getpid())
    print(syscall.call(21, uint64("0xffffffffffffffff")))
    print(fcall(uint64("0x123456789abcdef0"), 42))
    local ok, err = pcall(syscall.call, 999)
    assert(not ok and string.find(err, "native failure"))
  `);
  assert.deepEqual(nativeLines, ['0xfedcba9889abcdef', '0xfedcba9889abcdef', '0x7']);
  assert.equal(calls[0][0], 20);
  assert.deepEqual(calls[1][1], new Int64(0xffffffff,0xffffffff));
  assert.deepEqual(calls[2][0], new Int64(0x9abcdef0,0x12345678));
  assert.deepEqual(calls[2][1], new Int64(42,0));
  await assert.rejects(nativeRun('uint64(9007199254740992.0)'), /exact integer/);
  await assert.rejects(nativeRun('syscall.call("0x100000000")'), /32 bits/);
  await assert.rejects(nativeRun('syscall.call(1,0,0,0,0,0,0,0)'), /six arguments/);
  await nativeRun('local ok = coroutine.resume(coroutine.create(function() syscall.getpid() end)); assert(not ok)');
  const memoryBytes = new Uint8Array(4096);
  const memoryBase = 0x123400000000;
  function offset(pointer) {
    const at = pointer.hi * 4294967296 + pointer.low - memoryBase;
    assert(at >= 0 && at < memoryBytes.length, 'full-width address must survive');
    return at;
  }
  let allocations = 0;
  nativeApi.p = {
    malloc: (size, type) => {
      assert.equal(type, 1);
      allocations++;
      return new Int64(memoryBase >>> 0, Math.floor(memoryBase / 4294967296));
    },
  };
  for (const width of [1,2,4,8]) {
    nativeApi.p['write'+width] = (pointer, number) => {
      const at = offset(pointer);
      let n = width === 8 ? (BigInt(number.hi) << 32n) | BigInt(number.low) : BigInt(number);
      for (let i=0;i<width;i++) { memoryBytes[at+i] = Number(n & 255n); n >>= 8n; }
    };
    nativeApi.p['read'+width] = pointer => {
      const at = offset(pointer);
      let n = 0n;
      for (let i=width-1;i>=0;i--) n = (n << 8n) | BigInt(memoryBytes[at+i]);
      return width === 8 ? new Int64(Number(n & 0xffffffffn),Number(n >> 32n)) : Number(n);
    };
  }
  await nativeRun(fs.readFileSync(path.resolve(__dirname, '../../payloads/lua/memory_smoke.lua'), 'utf8'));
  assert.equal(allocations, 1);
  assert(nativeLines.includes('memory round trip OK\t0x123400000000'));
  await nativeRun('local p = memory.alloc(1); memory.write_buffer(p, ""); assert(memory.read_buffer(p, 0) == "")');
  await assert.rejects(nativeRun('memory.alloc(0)'), /positive size/);
  await assert.rejects(nativeRun('memory.alloc(65536)'), /budget exceeded/);
  await assert.rejects(nativeRun('memory.read_buffer(0, -1)'), /64 KiB/);
  await assert.rejects(nativeRun('memory.write64(uint64("0xffffffffffffffff"), 0)'), /wraps/);
  nativeApi.p.read1 = () => { throw Error('guarded read'); };
  await nativeRun('local ok, err = pcall(memory.read8, 1); assert(not ok and string.find(err, "guarded read"))');
  console.log('Lua payload tests passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
