const {lua, to_luastring: str} = require('fengari');
const DECIMAL_FLOAT = str('%.0f');

// Keep wide conversion checks off the common formatting path.
function tryWideFormat(s, count, value) {
  // Preserve fallback semantics for flags, widths and negative %u values.
  if (count === 2 && lua.lua_type(s, 1) === lua.LUA_TSTRING) {
    const fmt = lua.lua_tolstring(s, 1);
    if (fmt.length === 2 && fmt[0] === 37) {
      const kind = fmt[1], type = lua.lua_type(s, 2);
      const n = type === lua.LUA_TNUMBER ? lua.lua_tonumber(s, 2) : NaN;
      const wide = Number.isInteger(n) && (n < -2147483648 || n > 2147483647);
      if (value && (kind === 120 || kind === 88) &&
          (type === lua.LUA_TUSERDATA || wide)) {
        let hex;
        try { hex = value(s, 2).toString(16); }
        catch (_) { /* Preserve fallback errors for invalid operands. */ }
        if (hex !== undefined) {
          lua.lua_pushstring(s, str(kind === 88 ? hex.toUpperCase() : hex));
          return true;
        }
      }
      if (wide && (kind === 100 || kind === 105 || kind === 117)) {
        // Use the same core float conversion as the old wrapper; JS decimal
        // conversion differs for large magnitudes and rounding boundaries.
        lua.lua_pushvalue(s, lua.lua_upvalueindex(1));
        lua.lua_pushstring(s, DECIMAL_FLOAT);
        lua.lua_pushvalue(s, 2);
        lua.lua_callk(s, 2, 1, 0, () => 1);
        return true;
      }
    }
  }
  return false;
}

// Capture the core formatter and compatibility fallback as Lua upvalues.
module.exports = function formatFactory(L, value) {
  lua.lua_pushvalue(L, 1);
  lua.lua_pushvalue(L, 2);
  lua.lua_pushcclosure(L, s => {
    const count = lua.lua_gettop(s);
    let fast = lua.lua_type(s, 1) === lua.LUA_TSTRING;
    for (let i = 2; fast && i <= count; i++) {
      const type = lua.lua_type(s, i);
      if (type === lua.LUA_TNUMBER) {
        const n = lua.lua_tonumber(s, i);
        // Wide integral floats require the existing hex/decimal rewrite.
        if (!Number.isFinite(n) || (Number.isInteger(n) &&
            (n < -2147483648 || n > 2147483647))) fast = false;
      } else if (type !== lua.LUA_TSTRING) fast = false;
    }
    if (fast) {
      for (let i = 2; i <= count; i++) {
        if (lua.lua_type(s, i) === lua.LUA_TNUMBER) {
          const n = lua.lua_tonumber(s, i);
          if (Number.isInteger(n)) {
            lua.lua_pushinteger(s, n);
            lua.lua_replace(s, i);
          }
        }
      }
    }
    if (!fast && tryWideFormat(s, count, value)) return 1;
    lua.lua_pushvalue(s, lua.lua_upvalueindex(fast ? 1 : 2));
    lua.lua_insert(s, 1);
    // Do not catch Fengari's yield sentinel: fallback metamethods may yield.
    lua.lua_callk(s, count, 1, 0, () => 1);
    return 1;
  }, 2);
  return 1;
};
