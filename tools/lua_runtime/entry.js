const { install } = require('./bridge');
const { lua, lauxlib, lualib, to_luastring, to_jsstring } = require('fengari');
const { psluaLiterals } = require('./pslua_literals');

// One state per invocation: no Lua globals or references survive a payload.
async function run(api, source, name = '=payload.lua') {
  const L = lauxlib.luaL_newstate();
  const output = [];
  let outputBytes = 0;
  let failure;
  const service = (api.args || []).includes("service=1");
  let cleanup;
  try {
    lualib.luaL_openlibs(L);
    // Bound synchronous VM work; the loader deadline cannot interrupt JavaScript.
    let ticks = 0;
    const compat = (api.args || []).includes("compat=remote_lua_loader");
    lua.lua_sethook(L, function (state) {
      if (++ticks >= 1000)
        lauxlib.luaL_error(state, to_luastring('Lua instruction budget exceeded'));
    }, lua.LUA_MASKCOUNT, 1000);
    const resume = install(L, api, { onResume: () => { if (service || compat) ticks = 0; } });
    lua.lua_pushcfunction(L, function (state) {
      const parts = [];
      const count = lua.lua_gettop(state);
      for (let i = 1; i <= count; i++) {
        const bytes = lauxlib.luaL_tolstring(state, i);
        outputBytes += bytes.length;
        if (outputBytes > 1024 * 1024)
          return lauxlib.luaL_error(state, to_luastring('Lua output budget exceeded'));
        parts.push(to_jsstring(bytes, 0, undefined, true));
        lua.lua_pop(state, 1);
      }
      outputBytes += count + 1;
      if (outputBytes > 1024 * 1024)
        return lauxlib.luaL_error(state, to_luastring('Lua output budget exceeded'));
      const line = parts.join('\t');
      if ((service || compat) && lua.lua_isyieldable(state)) {
        outputBytes = 0;
        return resume.suspend(state, () => api.log(line), () => 0);
      }
      output.push(line);
      return 0;
    });
    lua.lua_setglobal(L, to_luastring('print'));
    // Do not expose browser I/O/module loading or allow scripts to remove the hook.
    for (const global of ['io', 'os', 'package', 'require', 'dofile', 'loadfile', 'debug']) {
      lua.lua_pushnil(L);
      lua.lua_setglobal(L, to_luastring(global));
    }
    if ((api.args || []).includes('compat=remote_lua_loader')) {
      cleanup = require('./compat/remote_lua_loader')(L, api, { ...resume.capabilities, suspend: resume.suspend });
      source = psluaLiterals(source);
    }
    const bytes = to_luastring(source);
    let status = lauxlib.luaL_loadbufferx(L, bytes, bytes.length, to_luastring(name), to_luastring('t'));
    if (status === lua.LUA_OK) {
      if (service) api.setPayloadTimeout(0);
      status = await resume();
    }
    if (status !== lua.LUA_OK) {
      const message = lua.lua_tolstring(L, -1);
      throw new Error(message ? to_jsstring(message, 0, undefined, true) : 'Lua raised a non-string error');
    }
    lua.lua_getglobal(L, to_luastring('IS_KEXP'));
    if (lua.lua_toboolean(L, -1)) {
      if (!api.krw) api.krw = { dead: true };
    }
    lua.lua_pop(L, 1);
  } catch (error) {
    failure = error;
  } finally {
    lua.lua_close(L);
    if (cleanup) {
      try { await cleanup(); }
      catch (error) { if (!failure) failure = error; }
    }
  }
  // Lua C functions are synchronous; drain logs in order before reporting errors.
  for (const line of output) await api.log(line);
  if (failure) throw failure;
}

module.exports = { run };
