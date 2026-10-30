const assert = require('node:assert/strict');
const {lua, lauxlib} = require('fengari');
const {pushOwnedBytes} = require('./owned_string');

// Source-level check that transfer actually avoids a duplicate buffer.
// memory_bulk_test.mjs covers string behavior through the shipped bundle.
for (const bytes of [new Uint8Array(0), Uint8Array.of(65, 0, 255, 128)]) {
  const L = lauxlib.luaL_newstate();
  pushOwnedBytes(L, bytes);
  assert.equal(lua.lua_type(L, -1), lua.LUA_TSTRING);
  assert.equal(lua.lua_tolstring(L, -1), bytes);
  lua.lua_close(L);
}
console.log('Owned Lua string tests passed');
