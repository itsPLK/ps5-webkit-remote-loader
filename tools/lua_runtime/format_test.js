const assert = require('node:assert/strict');
const fs = require('node:fs');
const {lua, lauxlib, lualib, to_luastring: str, to_jsstring} = require('fengari');
const L = lauxlib.luaL_newstate();
lualib.luaL_openlibs(L);
lua.lua_pushcfunction(L, require('./compat/format'));
lua.lua_setglobal(L, str('factory'));
const source = fs.readFileSync(__dirname + '/compat/remote_lua_loader.lua', 'utf8');
const wrapper = source.slice(source.indexOf('local core_format ='), source.indexOf('string.format = __compat_format'));
const script = `
function is_uint64(v) return type(v) == 'userdata' end
${wrapper}
local old = string.format
local fallback_calls = 0
local fast = factory(core_format, function(...)
    fallback_calls = fallback_calls + 1
    return old(...)
end)
local function compare(...)
    local a, av = pcall(old, ...)
    local b, bv = pcall(fast, ...)
    assert(a == b)
    if a then assert(av == bv, tostring(av) .. ' ~= ' .. tostring(bv)) end
end
for _, fmt in ipairs({'%d', '%i', '%u', '%o', '%x', '%X', '%+08d', '%#08x',
    '%-12.5d', '%s', '%q', '%c', '%% %d', '%.2f', '%e', '%g', '%a'}) do
    for _, n in ipairs({0, -0.0, 1, -1, 1.0, -1.0, 1.25, -1.25,
        -2147483648.0, 2147483647.0}) do compare(fmt, n) end
end
compare('literal')
compare('binary\\0\\255%s', 'a\\0\\255')
compare('%s %d %s %.2f', 'first', 42.0, 'last', 3.25)
compare('%s %s', '12', '3')
compare('%d', '12')
compare('%%d %d', 3)
compare('%')
compare('%z', 1)
compare('%999d', 1)
compare('%d')
compare('literal', 1, 'extra')
assert(fallback_calls == 0)
compare('%s', nil)
compare('%s', true)
compare('%s', setmetatable({}, {__tostring=function() return 'object' end}))
compare('%f', math.huge)
compare('%f', 0/0)
compare('%d', 4294967295.0)
compare('%s', 4294967295.0)
compare(123)
assert(fallback_calls == 7, 'fallback count ' .. fallback_calls)
for _, fmt in ipairs({'%d', '%i', '%u', '%08d', '%+d', 'value=%d', '%s'}) do
    for _, n in ipairs({2147483648.0, -2147483649.0, 4294967295.0,
        9007199254740991.0, -9007199254740991.0, 1e21, -1e21, 1e100}) do
        compare(fmt, n)
    end
end
local yielding = factory(core_format, function() coroutine.yield('paused'); return 'resumed' end)
local co = coroutine.create(function() return yielding('%s', {}) end)
local ok, result = coroutine.resume(co)
assert(ok and result == 'paused', tostring(ok) .. ':' .. tostring(result))
ok, result = coroutine.resume(co)
assert(ok and result == 'resumed', tostring(ok) .. ':' .. tostring(result))
`;
const status = lauxlib.luaL_dostring(L, str(script));
assert.equal(status, lua.LUA_OK, status ? to_jsstring(lua.lua_tostring(L, -1)) : '');
console.log('formatter fast path differential and yield tests passed');
