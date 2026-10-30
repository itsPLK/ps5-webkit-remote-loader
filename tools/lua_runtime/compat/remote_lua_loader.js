// Optional profile. Core bridge code has no knowledge of this module.
const {lua, lauxlib, to_luastring: str} = require('fengari');
const { psluaLiterals } = require('../pslua_literals');
// The profile is loaded as text, so its own literals need the same double spelling
// the payload gets: Fengari truncates 0x300000000 (sysctl name translation) to 0.
const source = psluaLiterals(require('./remote_lua_loader.lua'));
module.exports = function install(L, api, cap) {
  const {value, push, bind, native, suspend} = cap;
  lauxlib.luaL_getmetatable(L, str('wkrl.uint64'));
  bind(L, s => {
    const key = lua.lua_tojsstring(s, 2);
    if (key === 'h' || key === 'l') {
      const n = value(s,1);
      lua.lua_pushnumber(s, Number(key === 'h' ? n >> BigInt(32) : n & BigInt('0xffffffff')));
    } else if (key === 'tonumber') {
      bind(s, state => {
        const n = BigInt.asIntN(64,value(state,1));
        const number = Number(n);
        if (!Number.isSafeInteger(number)) throw Error('uint64:tonumber would lose precision');
        lua.lua_pushnumber(state,number); return 1;
      });
    } else if (key === 'pack') {
      bind(s, state => {
        let n = value(state,1); const bytes = new Uint8Array(8);
        for (let i=0;i<8;i++) { bytes[i]=Number(n & BigInt(255)); n >>= BigInt(8); }
        lua.lua_pushlstring(state,bytes,8); return 1;
      });
    } else lua.lua_pushnil(s);
    return 1;
  });
  lua.lua_setfield(L,-2,str('__index')); lua.lua_pop(L,1);
  bind(L,s => {
    const bytes = lua.lua_tolstring(s,1);
    if (!bytes || bytes.length > 8) throw Error('uint64.unpack expects at most eight bytes');
    let n = BigInt(0);
    for(let i=bytes.length-1;i>=0;i--) n=(n << BigInt(8)) | BigInt(bytes[i]);
    push(s,n); return 1;
  });
  lua.lua_setglobal(L,str('__compat_unpack'));
  bind(L, s => {
    const ts = Number(BigInt.asIntN(64, value(s, 1)));
    const d = new Date(ts * 1000);
    const year = d.getUTCFullYear();
    const startOfYear = Date.UTC(year, 0, 1);
    const yday = Math.floor((d.getTime() - startOfYear) / 86400000);
    const fields = [
      d.getUTCSeconds(), d.getUTCMinutes(), d.getUTCHours(),
      d.getUTCDate(), d.getUTCMonth(), year - 1900, d.getUTCDay(), yday
    ];
    for (const f of fields) lua.lua_pushinteger(s, f | 0);
    return 8;
  });
  lua.lua_setglobal(L, str('__compat_gmtime_fields'));
  const regions = [];
  bind(L, s => {
    const addr = value(s, 1), size = value(s, 2);
    regions.push({ addr, size });
    return 0;
  });
  lua.lua_setglobal(L, str('__compat_track_region'));
  bind(L, s => {
    const addr = value(s, 1);
    const idx = regions.findIndex(r => r.addr === addr);
    if (idx !== -1) regions.splice(idx, 1);
    return 0;
  });
  lua.lua_setglobal(L, str('__compat_untrack_region'));
  for (const [name, pointer] of Object.entries({
    eboot_base: api.libSceNKWebKitBase || { low: 0, hi: 0 },
    libc_base: api.libSceLibcInternalBase || { low: 0, hi: 0 },
    libkernel_base: api.libKernelBase || { low: 0, hi: 0 },
  })) {
    push(L,(BigInt(pointer.hi>>>0)<<BigInt(32))|BigInt(pointer.low>>>0));
    lua.lua_setglobal(L,str(name));
  }
  const gadgetSource = api.gadgets || (api.p && api.p.gadgets) || {};
  lua.lua_newtable(L);
  for (const [name, ptr] of Object.entries(gadgetSource)) {
    if (!ptr || typeof ptr.low !== 'number') continue;
    const val = (BigInt(ptr.hi >>> 0) << BigInt(32)) | BigInt(ptr.low >>> 0);
    push(L, val);
    lua.lua_setfield(L, -2, str(name));
    if (name !== 'ret' && name !== 'infloop' && !name.endsWith('; ret')) {
      push(L, val);
      lua.lua_setfield(L, -2, str(name + '; ret'));
    }
    if (name === 'shl rax, 3' || name === 'shl rax, 3; ret') {
      lua.lua_pushstring(L, str('__compat_shl_rax_cl'));
      lua.lua_setfield(L, -2, str('shl rax, cl; ret'));
    }
    if (name === 'add rax, rcx' || name === 'add rax, rcx; ret') {
      push(L, val);
      lua.lua_setfield(L, -2, str('add rax, r8; ret'));
    }
  }
  lua.lua_setglobal(L, str('gadgets'));

  const syscallSource = api.syscalls || (api.p && api.p.syscalls) || {};
  lua.lua_newtable(L);
  for (const [numStr, ptr] of Object.entries(syscallSource)) {
    if (!ptr || typeof ptr.low !== 'number') continue;
    const val = (BigInt(ptr.hi >>> 0) << BigInt(32)) | BigInt(ptr.low >>> 0);
    push(L, val);
    lua.lua_rawseti(L, -2, Number(numStr));
  }
  lua.lua_setglobal(L, str('__compat_syscall_addrs'));

  lua.lua_pushcfunction(L, s => {
    if (!api.chain || typeof api.chain.run !== 'function' || typeof api.chain.add_syscall !== 'function') {
      lua.lua_pushboolean(s, false);
      return 1;
    }
    try {
      const len = lauxlib.luaL_len(s, 1);
      api.chain.clear();
      for (let i = 1; i <= len; i++) {
        lua.lua_rawgeti(s, 1, i);
        lua.lua_getfield(s, -1, str('kind'));
        const kind = lua.lua_tojsstring(s, -1);
        lua.lua_pop(s, 1);
        if (kind === 'write64') {
          lua.lua_getfield(s, -1, str('addr'));
          const addr = native(value(s, -1));
          lua.lua_pop(s, 1);
          lua.lua_getfield(s, -1, str('val'));
          const val = native(value(s, -1));
          lua.lua_pop(s, 1);
          api.chain.push_write8(addr, val);
        } else if (kind === 'write32') {
          lua.lua_getfield(s, -1, str('addr'));
          const addr = native(value(s, -1));
          lua.lua_pop(s, 1);
          lua.lua_getfield(s, -1, str('val'));
          const val = Number(value(s, -1) & BigInt('0xffffffff')) >>> 0;
          lua.lua_pop(s, 1);
          api.p.write4(addr, val);
        } else if (kind === 'syscall' || kind === 'fcall') {
          let target;
          if (kind === 'syscall') {
            lua.lua_getfield(s, -1, str('num'));
            target = Number(value(s, -1));
            lua.lua_pop(s, 1);
          } else {
            lua.lua_getfield(s, -1, str('rip'));
            target = native(value(s, -1));
            lua.lua_pop(s, 1);
          }
          const callArgs = [];
          lua.lua_getfield(s, -1, str('args'));
          for (let j = 1; j <= 6; j++) {
            lua.lua_rawgeti(s, -1, j);
            if (!lua.lua_isnil(s, -1)) {
              callArgs.push(native(value(s, -1)));
            } else {
              callArgs.push(undefined);
            }
            lua.lua_pop(s, 1);
          }
          lua.lua_pop(s, 1);
          while (callArgs.length > 0 && callArgs[callArgs.length - 1] === undefined) {
            callArgs.pop();
          }
          lua.lua_getfield(s, -1, str('ret_addr'));
          const hasRet = !lua.lua_isnil(s, -1);
          const retAddr = hasRet ? native(value(s, -1)) : null;
          lua.lua_pop(s, 1);
          if (kind === 'syscall') {
            if (hasRet) api.chain.add_syscall_ret(retAddr, target, ...callArgs);
            else api.chain.add_syscall(target, ...callArgs);
          } else {
            api.chain.fcall(target, ...callArgs);
            if (hasRet) api.chain.write_result(retAddr);
          }
        }
        lua.lua_pop(s, 1);
      }
    } catch (e) {
      return lauxlib.luaL_error(s, str(String(e.message || e)));
    }
    return suspend(s, () => api.chain.run(), state => {
      lua.lua_pushboolean(state, true);
      return 1;
    });
  });
  lua.lua_setglobal(L, str('__compat_run_rop_batch'));

  // api.prefetchKexp() lives in the payload api, so the fetch has to happen on the
  // JS side of the bridge. It yields the main coroutine while the host fetches the
  // shared/ files, then hands both binaries over as Lua strings.
  lua.lua_pushcfunction(L, s => {
    if (typeof api.prefetchKexp !== 'function') {
      return lauxlib.luaL_error(s, str('prefetchKexp is missing from the payload api'));
    }
    return suspend(s, () => api.prefetchKexp(), (state, prefetched) => {
      const kexp = prefetched && prefetched.kexpBytes;
      const elf = prefetched && prefetched.elfldrBytes;
      if (!(kexp instanceof Uint8Array) || !(elf instanceof Uint8Array)) {
        return lauxlib.luaL_error(state, str('prefetchKexp returned no binary bytes'));
      }
      lua.lua_pushlstring(state, kexp, kexp.length);
      lua.lua_pushlstring(state, elf, elf.length);
      return 2;
    });
  });
  lua.lua_setglobal(L, str('__compat_shared_prefetch'));

  // The .js kernel exploits take their import addresses from window.SYMBOLS (one
  // table per firmware in offsets/). The Lua side has no window, so the bridge
  // hands the resolved absolute addresses over; kexp needs them for its api table.
  const symbolSource = (typeof window !== "undefined" && window.SYMBOLS) || {};
  const symbolBases = {
    libkernel: api.libKernelBase || { low: 0, hi: 0 },
    libc: api.libSceLibcInternalBase || { low: 0, hi: 0 },
  };
  const toBigInt = (pointer) => (BigInt(pointer.hi >>> 0) << BigInt(32)) | BigInt(pointer.low >>> 0);
  lua.lua_newtable(L);
  for (const [group, table] of Object.entries(symbolSource)) {
    const base = symbolBases[group];
    if (!base) continue;
    lua.lua_newtable(L);
    for (const [name, offset] of Object.entries(table)) {
      if (typeof offset !== "number") continue;
      push(L, toBigInt(base) + BigInt(offset));
      lua.lua_setfield(L, -2, str(name));
    }
    lua.lua_setfield(L, -2, str(group));
  }
  lua.lua_setglobal(L, str('symbols'));

  lua.lua_pushstring(L,str(api.fw || 'unknown')); lua.lua_setglobal(L,str('FW_VERSION'));
  const bytes = str(source);
  const status = lauxlib.luaL_loadbufferx(L,bytes,bytes.length,str('=compat/remote_lua_loader.lua'),str('t'));
  if (status !== lua.LUA_OK || lua.lua_pcall(L,0,0,0) !== lua.LUA_OK)
    throw Error(lua.lua_tojsstring(L,-1));
  return async function cleanup() {
    if (!api.chain || typeof api.chain.syscall !== 'function') return;
    const { native } = cap;
    for (const r of regions.splice(0)) {
      await api.chain.syscall(73, native(r.addr), native(r.size));
    }
  };
};
