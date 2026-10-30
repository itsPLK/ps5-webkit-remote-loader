const { lua, lauxlib, to_luastring: str, to_jsstring } = require('fengari');
const ZERO = BigInt(0), WIDTH = BigInt(64), MASK = (BigInt(1) << WIDTH) - BigInt(1);
const META = str('wkrl.uint64');

function install(L, api, { onResume = () => {} } = {}) {
  let pending = null;
  let completion;
  let pushMetatable, metatableIdentity;
  function value(state, index) {
    const type = lua.lua_type(state, index);
    if (type === lua.LUA_TUSERDATA) {
      const boxed = lua.lua_touserdata(state, index);
      if (lua.lua_getmetatable(state, index)) {
        const matches = lua.lua_topointer(state, -1) === metatableIdentity;
        lua.lua_pop(state, 1);
        if (matches) return boxed.value;
      }
    }
    if (type === lua.LUA_TSTRING) {
      const text = to_jsstring(lua.lua_tolstring(state, index));
      if (!/^(?:0x[0-9a-f]+|[+-]?[0-9]+)$/i.test(text)) throw Error('invalid uint64 string');
      return BigInt(text) & MASK;
    }
    if (type === lua.LUA_TNUMBER) {
      const n = lua.lua_tonumber(state, index);
      if (!Number.isSafeInteger(n)) throw Error('uint64 requires an exact integer or string');
      return BigInt(n) & MASK;
    }
    throw Error('expected uint64, integer, or integer string');
  }
  function push(state, n) {
    lua.lua_newuserdata(state, 0).value = n & MASK;
    pushMetatable(state);
    lua.lua_setmetatable(state, -2);
  }
  function bind(state, fn) {
    lua.lua_pushcfunction(state, s => {
      try { return fn(s); }
      catch (e) { return lauxlib.luaL_error(s, str(String(e.message || e))); }
    });
  }
  lauxlib.luaL_newmetatable(L, META);
  // State-local proxies also work in that state's child coroutines. Compare the
  // actual metatable identity without a registry lookup for every operand.
  pushMetatable = lua.lua_toproxy(L, -1);
  metatableIdentity = lua.lua_topointer(L, -1);
  function shift(a, b) {
    b = BigInt.asIntN(64, b);
    if (b >= WIDTH || b <= -WIDTH) return ZERO;
    return b < ZERO ? a >> -b : a << b;
  }
  const binary = {
    __add: (a,b) => a+b, __sub: (a,b) => a-b, __mul: (a,b) => a*b,
    __band: (a,b) => a&b, __bor: (a,b) => a|b, __bxor: (a,b) => a^b,
    __shl: (a,b) => shift(a,b),
    __shr: (a,b) => shift(a, -BigInt.asIntN(64,b)),
  };
  for (const [name, op] of Object.entries(binary)) {
    bind(L, s => { push(s, op(value(s,1), value(s,2))); return 1; });
    lua.lua_setfield(L, -2, str(name));
  }
  for (const [name, op] of Object.entries({__eq:(a,b)=>a===b, __lt:(a,b)=>a<b, __le:(a,b)=>a<=b})) {
    bind(L, s => { lua.lua_pushboolean(s, op(value(s,1),value(s,2))); return 1; });
    lua.lua_setfield(L,-2,str(name));
  }
  bind(L, s => { lua.lua_pushstring(s,str('0x'+value(s,1).toString(16))); return 1; });
  lua.lua_setfield(L,-2,str('__tostring'));
  lua.lua_pushboolean(L,false);
  lua.lua_setfield(L,-2,str('__metatable'));
  lua.lua_pop(L,1);
  bind(L,s => { push(s,value(s,1)); return 1; });
  lua.lua_setglobal(L,str('uint64'));

  function native(n) {
    return new api.int64(Number(n & BigInt('0xffffffff')), Number(n >> BigInt(32)));
  }
  const memoryBindings = require('./memory')(L, api, { value, push, bind, native });
  function call(s, syscall) {
    if (s !== L) return lauxlib.luaL_error(s,str('native calls require the main Lua coroutine'));
    const count = lua.lua_gettop(s);
    if (count < 1 || count > 7) return lauxlib.luaL_error(s,str('native calls accept a target and up to six arguments'));
    let target, args;
    try {
      const n = value(s,1);
      if (syscall && n > BigInt('0xffffffff')) throw Error('syscall number exceeds 32 bits');
      target = syscall ? Number(n) : native(n);
      args = [];
      for (let i=2;i<=count;i++) args.push(native(value(s,i)));
    } catch(e) { return lauxlib.luaL_error(s,str(e.message)); }
    return suspend(s, () => api.chain[syscall ? 'syscall' : 'call'](target,...args), (state,result) => {
      push(state,(BigInt(result.hi >>> 0) << BigInt(32)) | BigInt(result.low >>> 0));
      return 1;
    });
  }
  function suspend(s, invoke, finish) {
    if (s !== L) return lauxlib.luaL_error(s,str('host operations require the main Lua coroutine'));
    pending = invoke;
    return lua.lua_yieldk(s,0,0,state => {
      if (completion.error) {
        lua.lua_pushstring(state,str(String(completion.error.message || completion.error)));
        return lua.lua_error(state);
      }
      return finish(state,completion.result);
    });
  }

  lua.lua_pushcfunction(L,s=>call(s,false));
  lua.lua_setglobal(L,str('fcall'));
  lua.lua_newtable(L);
  lua.lua_pushcfunction(L,s=>call(s,true));
  lua.lua_setfield(L,-2,str('call'));
  lua.lua_pushcfunction(L,s=>{ lua.lua_pushinteger(s,20); lua.lua_insert(s,1); return call(s,true); });
  lua.lua_setfield(L,-2,str('getpid'));
  lua.lua_setglobal(L,str('syscall'));
  async function resume() {
    let status = lua.lua_resume(L,null,0);
    while (status === lua.LUA_YIELD) {
      if (!pending) throw Error('unexpected Lua yield');
      const invoke = pending;
      pending = null;
      try { completion = {result: await invoke()}; }
      catch(error) { completion = {error}; }
      onResume();
      status = lua.lua_resume(L,null,0);
    }
    return status;
  }
  resume.suspend = suspend;
  resume.capabilities = { value, push, bind, native, ...memoryBindings };
  return resume;
}
module.exports = { install };
