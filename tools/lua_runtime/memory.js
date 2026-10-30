const { lua, to_luastring: str } = require('fengari');

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
    field('read' + bits, s => {
      const result = api.p['read' + bytes](native(address(s, bytes)));
      if (bits === 64) push(s, fromNative(result));
      else lua.lua_pushnumber(s, result >>> 0);
      return 1;
    });
    field('write' + bits, s => {
      const pointer = native(address(s, bytes));
      const n = value(s, 2);
      api.p['write' + bytes](pointer, bits === 64 ? native(n) : Number(n & ((BigInt(1) << BigInt(bits)) - BigInt(1))));
      return 0;
    });
  }
  field('read_buffer', s => {
    const n = size(s, 2), start = address(s, n);
    const buffer = new Uint8Array(n);
    for (let i=0;i<n;i++) buffer[i] = api.p.read1(native(start + BigInt(i)));
    lua.lua_pushlstring(s, buffer, n);
    return 1;
  });
  field('write_buffer', s => {
    // Require a real binary Lua string, avoiding implicit numeric conversions.
    if (lua.lua_type(s, 2) !== lua.LUA_TSTRING) throw Error('memory.write_buffer requires a Lua string');
    const buffer = lua.lua_tolstring(s, 2);
    if (buffer.length > LIMIT) throw Error('memory buffer exceeds 64 KiB limit');
    const start = address(s, buffer.length);
    for (let i=0;i<buffer.length;i++) api.p.write1(native(start + BigInt(i)), buffer[i]);
    return 0;
  });
  lua.lua_setglobal(L, str('memory'));
};
