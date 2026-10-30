const { lua, to_luastring: str } = require('fengari');
const {pushOwnedBytes} = require('./owned_string');

module.exports = function installMemory(L, api, { value, push, bind, native }) {
  const LIMIT = 64 * 1024;
  let allocated = 0;
  function size(s, index) {
    const n = value(s, index);
    if (n > BigInt(LIMIT)) throw Error('memory size exceeds 64 KiB limit');
    return Number(n);
  }
  function address(s, width) {
    const n = value(s, 1);
    if (n + BigInt(width) > (BigInt(1) << BigInt(64))) throw Error('memory address range wraps');
    return n;
  }
  function fromNative(n) {
    return (BigInt(n.hi >>> 0) << BigInt(32)) | BigInt(n.low >>> 0);
  }
  // These primitives are synchronous and do not retain their address argument.
  // Reuse one pointer, including carry into the high word, throughout a copy.
  function advance(pointer, bytes) {
    const low = (pointer.low + bytes) >>> 0;
    if (low < pointer.low) pointer.hi = (pointer.hi + 1) >>> 0;
    pointer.low = low;
  }
  // Profiles can request boxed scalar results without going through a Lua
  // wrapper and constructor. Both forms share validation and guarded reads.
  function scalarReader(bits, boxed = false) {
    const bytes = bits / 8;
    return s => {
      const result = api.p['read' + bytes](native(address(s, bytes)));
      if (bits === 64) push(s, fromNative(result));
      else if (boxed) push(s, BigInt(result >>> 0));
      else lua.lua_pushnumber(s, result >>> 0);
      return 1;
    };
  }
  lua.lua_newtable(L);
  function field(name, fn) {
    bind(L, fn);
    lua.lua_setfield(L, -2, str(name));
  }
  field('alloc', s => {
    const n = size(s, 1);
    if (!n) throw Error('memory.alloc requires a positive size');
    // The loader pins backing arrays for the session; budget includes its padding.
    if (allocated + n + 1000 > LIMIT) throw Error('memory allocation budget exceeded');
    const pointer = api.p.malloc(n, 1);
    allocated += n + 1000;
    push(s, fromNative(pointer));
    return 1;
  });
  for (const bits of [8,16,32,64]) {
    const bytes = bits / 8;
    field('read' + bits, scalarReader(bits));
    field('write' + bits, s => {
      const pointer = native(address(s, bytes));
      const n = value(s, 2);
      api.p['write' + bytes](pointer, bits === 64 ? native(n) : Number(n & ((BigInt(1) << BigInt(bits)) - BigInt(1))));
      return 0;
    });
  }
  function readBuffer(s) {
    const n = size(s, 2), pointer = native(address(s, n));
    const buffer = new Uint8Array(n);
    if (typeof api.p.readInto === 'function') {
      api.p.readInto(pointer, buffer);
      pushOwnedBytes(s, buffer);
      return 1;
    }
    let i = 0;
    // Align before widening; never read outside the requested byte range.
    while (i < n && (pointer.low & 3)) {
      buffer[i++] = api.p.read1(pointer);
      advance(pointer, 1);
    }
    while (i + 4 <= n) {
      const word = api.p.read4(pointer);
      buffer[i++] = word;
      buffer[i++] = word >>> 8;
      buffer[i++] = word >>> 16;
      buffer[i++] = word >>> 24;
      advance(pointer, 4);
    }
    while (i < n) {
      buffer[i++] = api.p.read1(pointer);
      advance(pointer, 1);
    }
    pushOwnedBytes(s, buffer);
    return 1;
  }
  function writeBuffer(s, returnPointer = false) {
    // Require a real binary Lua string, avoiding implicit numeric conversions.
    if (lua.lua_type(s, 2) !== lua.LUA_TSTRING) throw Error('memory.write_buffer requires a Lua string');
    const buffer = lua.lua_tolstring(s, 2);
    if (buffer.length > LIMIT) throw Error('memory buffer exceeds 64 KiB limit');
    const start = address(s, buffer.length);
    // An empty compatibility write validates and returns its pointer without
    // touching native memory. Core writes retain their existing behavior.
    if (returnPointer && !buffer.length) { push(s, start); return 1; }
    writeBytes(native(start), buffer);
    if (returnPointer) { push(s, start); return 1; }
    return 0;
  }
  function writeBytes(pointer, buffer) {
    if (typeof api.p.writeBytes === 'function') {
      api.p.writeBytes(pointer, buffer);
      return;
    }
    let i = 0;
    while (i < buffer.length && (pointer.low & 3)) {
      api.p.write1(pointer, buffer[i++]);
      advance(pointer, 1);
    }
    while (i + 4 <= buffer.length) {
      const word = (buffer[i] | (buffer[i + 1] << 8) |
        (buffer[i + 2] << 16) | (buffer[i + 3] << 24)) >>> 0;
      api.p.write4(pointer, word);
      i += 4;
      advance(pointer, 4);
    }
    while (i < buffer.length) {
      api.p.write1(pointer, buffer[i++]);
      advance(pointer, 1);
    }
  }
  field('read_buffer', readBuffer);
  field('write_buffer', s => writeBuffer(s));
  lua.lua_setglobal(L, str('memory'));
  return {scalarReader, readBuffer, writeBuffer};
};
