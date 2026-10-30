const assert = require('node:assert/strict');
const {lua, lauxlib, to_luastring: str} = require('fengari');
const {install} = require('./bridge');

const states = [lauxlib.luaL_newstate(), lauxlib.luaL_newstate()];
try {
  const bridges = states.map(L => install(L, {}));
  for (let i = 0; i < states.length; i++) {
    const L = states[i], {value, push} = bridges[i].capabilities;
    push(L, 0xffffffffffffffffn);
    assert.equal(value(L, -1), 0xffffffffffffffffn);
    assert.equal(lua.lua_gettop(L), 1);
    lua.lua_pushnumber(L, -1);
    assert.equal(value(L, -1), 0xffffffffffffffffn);
    lua.lua_pop(L, 1);
    lua.lua_pushstring(L, str('0x123456789abcdef0'));
    assert.equal(value(L, -1), 0x123456789abcdef0n);
    lua.lua_pop(L, 1);

    // Neither a value-shaped userdata nor an unrelated metatable may impersonate
    // uint64. Rejections must leave the stack untouched, including negative indices.
    lua.lua_newuserdata(L, 0).value = 123n;
    assert.throws(() => value(L, -1), /expected uint64/);
    lauxlib.luaL_newmetatable(L, str('unrelated'));
    lua.lua_setmetatable(L, -2);
    assert.throws(() => value(L, -1), /expected uint64/);
    assert.equal(lua.lua_gettop(L), 2);
    lua.lua_pop(L, 1);
    lauxlib.luaL_getmetatable(L, str('unrelated'));
    lua.lua_setmetatable(L, -2);
    assert.throws(() => value(L, -1), /expected uint64/);
    assert.equal(lua.lua_gettop(L), 1);
    lua.lua_pop(L, 1);
  }
  // Closing one state must not invalidate the other state's cached metatable.
  lua.lua_close(states[0]);
  states[0] = null;
  bridges[1].capabilities.push(states[1], 42n);
  assert.equal(bridges[1].capabilities.value(states[1], -1), 42n);
} finally {
  for (const L of states) if (L) lua.lua_close(L);
}
console.log('Lua bridge value and metatable tests passed');
