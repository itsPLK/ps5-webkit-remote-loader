const assert = require('node:assert/strict');
const fs = require('node:fs');
const {lua, lauxlib, lualib, to_luastring: str, to_jsstring} = require('fengari');
const source = fs.readFileSync(__dirname + '/../../payloads/lua/compat_bench_b.lua', 'utf8');
const summary = source.slice(source.indexOf('local function us_of(name)'));
const L = lauxlib.luaL_newstate();
lualib.luaL_openlibs(L);
const script = `
local cases = {
  {name='getpid control, 40 individual calls', n=3, times={240000}},
  {name='getpid post-chain control, 40 individual calls', n=3, times={120000}},
  {name='short sleep quantization (10 x 1 ms)', n=10, times={10000}},
  {name='long sleep quantization (3 x 50 ms)', n=3, times={150000}}
}
local function stats(times) return times[1] end
local R1,S1,K1,F1,SL1 = 0,0,0,0,40
local R2,S2,K2,F2,P2_ = 0,0,0,0,0
local checked = 0
function print() end
function printf(fmt, ...)
  local args = {...}
  if fmt:find('unit medians:', 1, true) then
    assert(args[1] == 2000, '40-call batch must be deaggregated once')
    checked = checked + 1
  elseif fmt:find('stream probe per-field', 1, true) then
    assert(args[3] == 1000, 'short sleep already normalized by case count')
    assert(args[4] == 50000, 'long sleep already normalized by case count')
    checked = checked + 1
  elseif fmt:find('reference phase totals estimate:', 1, true) then
    assert(args[1] == 2000, '40 long sleeps must contribute 2000 ms')
    checked = checked + 1
  end
end
${summary}
assert(checked == 3)
`;
const status = lauxlib.luaL_dostring(L, str(script));
assert.equal(status, lua.LUA_OK, status ? to_jsstring(lua.lua_tostring(L, -1)) : '');
assert.equal((source.match(/add\("getpid control, 40 individual calls"/g) || []).length, 1);
console.log('Lua benchmark summary unit tests passed');
