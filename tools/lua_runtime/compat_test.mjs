import assert from 'node:assert/strict';
import fs from 'node:fs';
import {run} from '../../src/lua-vm.js';
import {int64} from '../../src/utils/int64.js';
const bytes = new Uint8Array(524288);
let cursor = 16;
let mmapCursor = 0x20000;
const calls = [], lines = [];
const view = new DataView(bytes.buffer);
const api = {
  args:['compat=remote_lua_loader'], int64, fw:'7.61',
  libSceNKWebKitBase: new int64(0x100000, 8),
  libSceLibcInternalBase: new int64(0x200000, 8),
  libKernelBase: new int64(0x300000, 8),
  gadgets: {
    'ret': new int64(0x100042, 8),
    'pop rsp': new int64(0x16eee1, 8),
    'pop rax': new int64(0x1a6cab, 8),
    'pop rdi': new int64(0x131434, 8),
    'pop rsi': new int64(0x1b7098, 8),
    'pop rdx': new int64(0x2478f7, 8),
    'pop rcx': new int64(0x132473, 8),
    'pop r8': new int64(0x5c6011, 8),
    'pop r9': new int64(0x3773c6, 8),
    'mov [rdi], rax': new int64(0x179337, 8),
    'mov [rdi], eax': new int64(0x179338, 8),
    'mov rax, [rax]': new int64(0x22a439, 8),
    'add rax, rcx': new int64(0x124321, 8),
    'cmp [rcx], eax': new int64(0x36f9349, 8),
    'inc dword [rax]': new int64(0x1b70b5, 8),
    'seta al': new int64(0x31a9c2, 8),
    'setb al': new int64(0x1a2b46, 8),
    'sete al': new int64(0x11cf1f, 8),
    'shl rax, 3': new int64(0x2588663, 8),
    'shl rax, 4': new int64(0x672966, 8),
  },
  syscalls: {
    20: new int64(0x3367a0, 8),
  },
  log:async line=>lines.push(line),
  p:{
    malloc:n=>{ const p=cursor; cursor+=n; return new int64(p); },
    read1:p=>bytes[p.low], write1:(p,v)=>{bytes[p.low]=v;},
    read2:p=>view.getUint16(p.low,true), write2:(p,v)=>view.setUint16(p.low,v,true),
    read4:p=>view.getUint32(p.low,true), write4:(p,v)=>view.setUint32(p.low,v,true),
    read8:p=>new int64(view.getUint32(p.low,true),view.getUint32(p.low+4,true)),
    write8:(p,v)=>{
      const lo = typeof v === 'number' ? (v>>>0) : v.low;
      const hi = typeof v === 'number' ? 0 : v.hi;
      view.setUint32(p.low,lo,true);
      view.setUint32(p.low+4,hi,true);
    },
  },
  chain:{
    syscall:async(n,...args)=>{
      calls.push([n,...args]);
      if (n===5) return new int64(0xffffffff,0xffffffff);
      if (n===477) {
        const len = args[1].low;
        const base = mmapCursor;
        mmapCursor += len;
        return new int64(base,0);
      }
      if (n===73) return new int64(0,0);
      if (n===116) {
        view.setUint32(args[0].low, 1793326020, true);
        view.setUint32(args[0].low+4, 0, true);
        view.setUint32(args[0].low+8, 123456, true);
        view.setUint32(args[0].low+12, 0, true);
        return new int64(0,0);
      }
        if (n===232) {
        view.setUint32(args[1].low, 12, true);
        view.setUint32(args[1].low+4, 0, true);
        view.setUint32(args[1].low+8, 500000000, true);
        view.setUint32(args[1].low+12, 0, true);
        return new int64(0,0);
      }
      if (n===209) return new int64(1,0);
      if (n===272) {
        view.setUint16(args[1].low + 4, 16, true);
        bytes[args[1].low + 7] = 4;
        bytes.set(new TextEncoder().encode("test"), args[1].low + 8);
        return new int64(16, 0);
      }
      if (n===240) return new int64(0,0);
      return new int64(77);
    },
    call:async(p,...args)=>{calls.push([p,...args]);return new int64(42);},
  },
};
await run(api, `
assert(syscall.getpid():tonumber() == 77)
syscall.resolve({getppid=39})
assert(syscall.getppid():tonumber() == 77)
assert(syscall.open("/tmp/a",0):tonumber() == -1)
assert(syscall.open("/tmp/b",0):tonumber() == -1)
assert(uint64("0x1234567887654321").h == 305419896)
assert(uint64("0x1234567887654321").l == 2271560481.0)
assert(uint64.unpack(ub8(uint64("0xfedcba9876543210"))) == uint64("0xfedcba9876543210"))
assert(uint64({h=1,l=2}) == uint64("0x100000002"))
local a, b = uint64(7), uint64(9)
assert(rawequal(a.tonumber, b.tonumber))
assert(rawequal(a.pack, b.pack))
local convert, pack = a.tonumber, a.pack
assert(convert(b) == 9 and convert(a) == 7)
assert(pack(a) == "\\7\\0\\0\\0\\0\\0\\0\\0")
assert(a.h == 0 and a.l == 7)
assert(a.unknown == nil and a[1] == nil and a[{}] == nil)
assert(not pcall(convert, {}) and not pcall(pack, false))
assert(uint64(-1):tonumber() == -1)
assert(uint64("9007199254740991"):tonumber() == 9007199254740991.0)
assert(not pcall(convert, uint64("9007199254740992")))
local clone = uint64(a)
assert(clone == a and not rawequal(clone, a))
assert(type(uint64) == "table" and type(uint64.unpack) == "function")
assert(__compat_make_uint64_constructor == nil)
assert(uint64({h="0x12345678", l=uint64("0x87654321")}) == uint64("0x1234567887654321"))
-- Match the old expression exactly, including non-32-bit fields and wrapping.
for _, h in ipairs({0, 1, -1, "0x100000001"}) do
    for _, l in ipairs({0, 1, -1, "0x200000002"}) do
        assert(uint64({h=h, l=l}) == ((uint64(h) << 32) | uint64(l)))
    end
end
for _, bad in ipairs({false, {}, {h=0}, {l=0}, {h=false,l=0}, "garbage", 1.5}) do
    assert(not pcall(uint64, bad))
end
assert(not pcall(uint64))
local fields = {}
local custom = setmetatable({}, {__index=function(_, key)
    fields[#fields + 1] = key
    return key == "h" and 1 or 2
end})
assert(uint64(custom) == uint64("0x100000002"))
assert(table.concat(fields) == "hl")
local yielding = coroutine.create(function()
    return uint64(setmetatable({}, {__index=function(_, key)
        coroutine.yield(key)
        return key == "h" and 1 or 2
    end}))
end)
local success, yielded = coroutine.resume(yielding)
assert(success and yielded == "h")
success, yielded = coroutine.resume(yielding)
assert(success and yielded == "l")
success, yielded = coroutine.resume(yielding)
assert(success and yielded == uint64("0x100000002"))
local ok, result = coroutine.resume(coroutine.create(function()
    return (a + b):tonumber()
end))
assert(ok and result == 16)
assert(not pcall(function() return uint64("0x1234567887654321"):tonumber() end))
local p=memory.alloc(16)
memory.write_dword(p,4294967295.0)
assert(memory.read_dword(p):tonumber()==4294967295.0)
assert(type(memory.read32(p)) == "number")
assert(type(memory.read_dword(p)) == "userdata")
local scalar = memory.alloc(32)
for _, row in ipairs({{"byte", "0xff"}, {"word", "0xffff"},
                      {"dword", "0xffffffff"}, {"qword", "0xffffffffffffffff"}}) do
    local read, write = memory["read_"..row[1]], memory["write_"..row[1]]
    write(scalar + 1, -1)
    local first, second = read(scalar + 1), read(scalar + 1)
    assert(type(first) == "userdata" and first == uint64(row[2]))
    assert(not rawequal(first, second))
    write(scalar + 1, 0)
    assert(read(scalar + 1) == uint64(0) and first == uint64(row[2]))
    assert(not pcall(read, {}))
end
memory.write_buffer(scalar, "\\1\\2\\3\\4\\5\\6\\7\\8")
assert(memory.read_qword(scalar) == uint64("0x0807060504030201"))
assert(memory.read_dword(scalar):tonumber() == 0x04030201)
assert(not pcall(memory.read_qword, uint64("0xfffffffffffffffc")))
local p2=memory.alloc(16)
assert(p2 ~= p, "allocations must return distinct addresses")
memory.free(p)
local p3=memory.alloc(16)
assert(p3 == p, "freed block must be reused")
assert(memory.read_dword(p3):tonumber()==0, "reused block must be zeroed")
local pinned = memory.alloc(16)
memory.write_dword(pinned, 0x12345678)
for i=1,300 do
    local b = memory.alloc(16)
    memory.write_dword(b, i)
end
assert(memory.read_dword(pinned):tonumber() == 0x12345678, "early allocations must not be overwritten by later loop allocations")
local tloc = memory.alloc(8)
local now = time(tloc):tonumber()
assert(now == 1793326020)
assert(memory.read_qword(tloc):tonumber() == 1793326020)
assert(os.time() == 1793326020)
assert(os.clock() == 12.5)
local tm = memory.alloc(36)
assert(gmtime_s(tloc, tm) == tm)
assert(memory.read_dword(tm + 0):tonumber() == 0)   -- sec
assert(memory.read_dword(tm + 4):tonumber() == 7)   -- min (02:07:00 UTC)
assert(memory.read_dword(tm + 8):tonumber() == 2)   -- hour
assert(memory.read_dword(tm + 12):tonumber() == 30) -- mday
assert(memory.read_dword(tm + 16):tonumber() == 9)  -- mon (Oct = 9)
assert(memory.read_dword(tm + 20):tonumber() == 126)-- year (2026 - 1900)
local gtm = gmtime(tloc)
assert(memory.read_dword(gtm + 12):tonumber() == 30)
assert(fcall(libc_addrofs.calloc)(4, 8) ~= uint64(0))
assert(fcall(uint64(123))(nil,4):tonumber()==42)
assert(eboot_base == uint64("0x800100000"))
assert(libc_base == uint64("0x800200000"))
assert(libkernel_base == uint64("0x800300000"))
local dbuf = memory.alloc(4096)
assert(syscall.getdents(5, dbuf, 4096):tonumber() == 16)
assert(memory.read_buffer(dbuf + 8, 4) == "test")
assert(syscall.accept(3, 0, 0):tonumber() == 77)
assert(syscall.getpid.syscall_no == 20)
local ok_err = run_with_coroutine(function()
    local pid = syscall.getpid():tonumber()
    assert(pid == 77)
end)
assert(ok_err == nil)
local caught = run_with_coroutine(function()
    syscall.getpid()
    error("boom_from_coroutine")
end)
assert(type(caught) == "string" and string.find(caught, "boom_from_coroutine"))
local rc = ropchain()
local sig = memory.alloc(8)
rc:push_write_qword_memory(sig, 123)
rc:push_syscall_with_ret(syscall.getpid)
rc:restore_through_longjmp()
assert(rc:execute_through_coroutine():tonumber() == 77)
assert(memory.read_qword(sig):tonumber() == 123)
local loop_rc = ropchain()
local flag_addr = memory.alloc(8)
loop_rc:gen_loop(flag_addr, "==", 0, function()
    loop_rc:push_increment_atomic_qword(flag_addr)
    loop_rc:gen_conditional(flag_addr, "~=", 0, function()
        loop_rc:push_set_rcx(12)
        loop_rc:push(gadgets["shl rax, cl; ret"])
        loop_rc:push_set_reg_from_rax("rsi")
        loop_rc:push_set_reg_from_memory("rdi", flag_addr)
    end)
end)
assert(require("ropchain") == true)
package.preload["custom_mod"] = function() return { answer = 42 } end
assert(require("custom_mod").answer == 42)
local SCE_KERNEL_ERROR_ESRCH = 0x80020003
local poll_err = memory.alloc(4)
memory.write_dword(poll_err, 0x80020003)
assert(memory.read_dword(poll_err):tonumber() == SCE_KERNEL_ERROR_ESRCH, "32-bit unsigned hex literal must match read_dword():tonumber()")
assert(string.format("0x%x", SCE_KERNEL_ERROR_ESRCH) == "0x80020003")
assert( kernel_offset.DATA_BASE_ALLPROC == 0x02859D50 )
storage.set("test_key", { a = uint64("0x1234"), b = "hello" })
assert(storage.get("test_key").a == uint64("0x1234"))
assert(bit32.band(255,15)==15)
assert(hex(uint64(77))=="0x4d")
printf("pid %d",syscall.getpid():tonumber())
`);
const openCalls = calls.filter(c => c[0] === 5);
assert.equal(openCalls.length, 2);
assert.equal(openCalls[0][1].low,openCalls[1][1].low,'scratch storage must be reused');
assert.equal(new TextDecoder().decode(bytes.subarray(openCalls[1][1].low,openCalls[1][1].low+7)),'/tmp/b\0');
const munmapCalls = calls.filter(c => c[0] === 73);
assert(munmapCalls.length >= 1, 'arena mmap regions must be munmapped on Lua state close');
assert.deepEqual(lines,['pid 77']);

lines.length = 0;
// Keep this compatibility example self-contained so a fresh checkout can run it.
const helloSource = `
  syscall.resolve({ getppid = 39 })
  local ids = { syscall.getpid():tonumber(), syscall.getppid():tonumber() }
  print("hello world from lua!")
  printf("platform %s (%s)", PLATFORM, FW_VERSION)
  printf("pid %d ppid %d", table.unpack(ids))
  for _, entry in ipairs({
    { "eboot", eboot_base },
    { "libc", libc_base },
    { "libkernel", libkernel_base },
  }) do
    printf("%s base @ %s", entry[1], hex(entry[2]))
  end
`;
await run(api, helloSource);
assert(lines.some(l => l.includes('hello world from lua!')), 'compatibility hello sample must run');
assert(lines.some(l => l.includes('eboot base @ 0x800100000')), 'compatibility hello sample must print eboot_base');

await run({...api,args:[]}, 'assert(type(uint64)=="function"); assert(memory.read_dword==nil); assert(syscall.resolve==nil); assert(os==nil); assert(time==nil); assert(not pcall(function() return uint64(1).tonumber end))');
const probeCalls = [];
let probeResult = new int64(0);
const probeApi = {...api, chain:{...api.chain, syscall:async(n,...args)=>{
  probeCalls.push([n,...args]);
  return n === 5 ? probeResult : new int64(0);
}}};
await run(probeApi,'assert(file_exists("/present"))');
assert.deepEqual(probeCalls.map(c=>c[0]),[5,6]);
assert.equal(probeCalls[0][2].low,0,'open must be read-only');
assert.equal(probeCalls[1][1].low,0,'descriptor zero must be closed');
probeCalls.length=0;
probeResult=new int64(0xffffffff,0xffffffff);
await run(probeApi,'assert(not file_exists("/missing"))');
assert.deepEqual(probeCalls.map(c=>c[0]),[5],'failed open must not be closed');
await run(probeApi,'assert(not pcall(file_exists,123))');
lines.length = 0;
const benchSource = fs.readFileSync(new URL('../../payloads/lua/compat_bench.lua', import.meta.url), 'utf8');
await run(api, benchSource);
assert(lines.some(l => l.includes('Lua arithmetic')));
assert(lines.some(l => l.includes('getpid syscall')));
assert.equal(lines.filter(l => l.startsWith('samples_us,')).length, 11);
assert(lines.includes('benchmark complete; checksums and buffer contents verified'));
assert(!lines.some(l => /NaN|Infinity/.test(l)), 'zero mock clock must not produce invalid rates');
// Exercise the direct write path and both sides of its chunk boundary through
// the shipped bundle, including binary contents, sentinels, and return values.
const bulkWrites = [];
const bulkApi = {...api, p: {...api.p, writeBytes: (pointer, data) => {
  bulkWrites.push({address: pointer.low, length: data.length});
  assert(data.length <= 65536);
  bytes.set(data, pointer.low);
}}};
const bulkBase = 0x40001;
for (const length of [0, 1, 64, 65535, 65536, 65537, 131073]) {
  bytes.fill(0xcc);
  bulkWrites.length = 0;
  await run(bulkApi, `
    local p = uint64(${bulkBase})
    local data = string.rep("A\\0\\255\\128", ${Math.ceil(length / 4)}):sub(1, ${length})
    assert(memory.write_buffer(p, data) == p)
  `);
  const expectedWrites = [];
  for (let offset = 0; offset < length; offset += 65536) {
    expectedWrites.push({address: bulkBase + offset, length: Math.min(65536, length - offset)});
  }
  assert.deepEqual(bulkWrites, expectedWrites);
  const pattern = [65, 0, 255, 128];
  for (let i = 0; i < length; i++) assert.equal(bytes[bulkBase + i], pattern[i % 4]);
  assert.equal(bytes[bulkBase - 1], 0xcc);
  assert.equal(bytes[bulkBase + length], 0xcc);
}
await run(bulkApi, `
  local p = uint64(${bulkBase})
  for _, address in ipairs({p, ${bulkBase}, "${bulkBase}", {h=0, l=${bulkBase}}}) do
    assert(memory.write_buffer(address, 123) == p)
    assert(memory.read_buffer(p, 3) == "123")
    assert(memory.write_buffer(address, "") == p)
  end
  assert(not pcall(memory.write_buffer, "invalid address", ""))
  assert(__compat_buffer_reader == nil and __compat_buffer_writer == nil)
  local data = "a\\0\\255b"
  local returned = memory.write_buffer(p, data)
  assert(returned == p and not rawequal(returned, p))
  assert(memory.read_buffer(p, #data) == data)
  assert(memory.read_buffer(p, uint64(#data)) == data)
  assert(memory.read_buffer(p, tostring(#data)) == data)
  assert(memory.read_buffer(p, 0) == "")
  assert(not pcall(memory.read_buffer, p, 65537))
  assert(not pcall(memory.read_buffer, p, -1))
  assert(not pcall(memory.read_buffer, p, 1.5))
  local ok, err = pcall(memory.read_buffer, p, uint64("9007199254740992"))
  assert(not ok and err:find("lose precision", 1, true))
  assert(not pcall(memory.write_buffer, uint64("0xffffffffffffffff"), "xx"))
  local custom = setmetatable({}, {__tostring=function() return data end})
  assert(memory.write_buffer(p, custom) == p)
  assert(memory.read_buffer(p, #data) == data)
  local co = coroutine.create(function()
    return memory.write_buffer(setmetatable({}, {__index=function(_, key)
      coroutine.yield(key)
      return key == "h" and 0 or ${bulkBase}
    end}), data)
  end)
  local success, result = coroutine.resume(co)
  assert(success and result == "h")
  success, result = coroutine.resume(co)
  assert(success and result == "l")
  success, result = coroutine.resume(co)
  assert(success and result == p)
  assert(memory.read_buffer(p, #data) == data)
`);
// Compare specialized uint64 conversions against the retained Lua wrapper.
const adapterSource = fs.readFileSync(new URL('./compat/remote_lua_loader.lua', import.meta.url), 'utf8');
const legacyFormatter = adapterSource.slice(adapterSource.indexOf('local core_format ='),
  adapterSource.indexOf('string.format = __compat_format'));
await run(api, `
local current = string.format
${legacyFormatter}
local legacy = string.format
string.format = current
local function compare(fmt, value, ...)
    local ok1, result1 = pcall(legacy, fmt, value, ...)
    local ok2, result2 = pcall(current, fmt, value, ...)
    assert(ok1 == ok2)
    if ok1 then assert(result1 == result2, fmt .. ': ' .. result1 .. ' ~= ' .. result2) end
end
for _, fmt in ipairs({'%x', '%X', '%08x', '0x%x', '%s %x', '%x %s', '%%x', '%z'}) do
    for _, text in ipairs({'0', '1', '2147483648', '4294967295',
        '0x1234567887654321', '0x8000000000000000', '0xffffffffffffffff'}) do
        compare(fmt, uint64(text))
        compare(fmt, uint64(text), 'extra')
    end
    for _, n in ipairs({-1, 2147483647.0, 2147483648.0, -2147483649.0,
        4294967295.0, 9007199254740991.0, 9007199254740992.0, 1.5, math.huge}) do
        compare(fmt, n)
    end
end
local n = uint64('0x1234567887654321')
for i = 1, 64 do
    n = (n << 1) + uint64(i)
    compare('%x', n)
    compare('%X', n)
end
assert(string.format('%x', uint64('0xffffffffffffffff')) == 'ffffffffffffffff')
assert(string.format('%X', uint64('0xabcdef1234567890')) == 'ABCDEF1234567890')
assert(__compat_format == nil)
`);
// A constant mock clock validates benchmark outputs, not performance.
const formatBenchmark = fs.readFileSync(new URL('../../payloads/lua/format_bench.lua', import.meta.url), 'utf8');
mmapCursor = 0x20000;
const start = lines.length;
await run(api, formatBenchmark);
assert(lines.slice(start).some(line => line.includes('formatter benchmark complete; outputs and checksums verified')));
console.log('Optional compatibility profile tests passed');
