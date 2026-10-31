const assert = require('node:assert/strict');
const fs = require('node:fs');
const {lua, lauxlib, lualib, to_luastring: str, to_jsstring} = require('fengari');
const root = __dirname + '/../..';
const fastSource = fs.readFileSync(root + '/payloads/lua/relapse.lua', 'utf8');
function pollFunction(source) {
  const start = source.indexOf('wait_for_pending_requests = function(candidate_ids, candidate_count, wanted_count)');
  const end = source.indexOf('\nend\n\nclaim_pending_requests = function', start);
  assert(start >= 0 && end > start);
  return source.slice(start, end + 4);
}
const implementation = pollFunction(fastSource);
function runScenario(fn, ready, newlyReady = []) {
  const L = lauxlib.luaL_newstate(); lualib.luaL_openlibs(L);
  const stateTable = '{' + Object.entries(ready).map(([id, state]) => '[' + id + ']=' + state).join(',') + '}';
  const laterTable = '{' + newlyReady.join(',') + '}';
  const setup = `
    local bytes, next_addr = {}, 4096
    local function word(v) return setmetatable({value=v}, {__index={tonumber=function(self) return self.value end}}) end
    bit32 = {band=function(a,b) return a & b end}
    memory = {
      alloc=function(n) local p=next_addr; next_addr=next_addr+n+16; return p end,
      write_dword=function(p,v) bytes[p]=type(v)=='table' and v.value or v end,
      read_dword=function(p) return word(bytes[p] or 0) end
    }
    local states = ${stateTable}
    local later = ${laterTable}
    local polls, polled_ids, sleeps = 0, 0, 0
    syscall = {aio_multi_poll=function(ids,n,out)
      polls=polls+1; polled_ids=polled_ids+n
      for i=0,n-1 do
        local id=memory.read_dword(ids+i*4):tonumber()
        memory.write_dword(out+i*4, states[id] or 2)
      end
      return 0
    end}
    sysint=function(fn,...) return fn(...) end
    sleep=function() sleeps=sleeps+1; for _,id in ipairs(later) do states[id]=1 end end
    local ticks=0
    fast_poll_now=function()
      ticks=ticks+1000000
      return math.floor(ticks/1000000000), ticks%1000000000
    end
    fast_poll_profile={scans=0,calls=0,ids=0,rounds=0,elapsed=0,clock_errors=0}
    local candidate_ids=memory.alloc(26*4)
    for i=0,25 do memory.write_dword(candidate_ids+i*4,i+1) end
    ${fn}
    local ok, result=pcall(wait_for_pending_requests,candidate_ids,26,18)
    local selected=''
    if ok then for i,v in ipairs(result) do selected=selected .. (i==1 and '' or ',') .. v end
    else selected=tostring(result) end
    return ok, selected, polls, polled_ids, sleeps,
      fast_poll_profile.calls, fast_poll_profile.ids, fast_poll_profile.rounds
  `;
  const status = lauxlib.luaL_loadbufferx(L, str(setup), setup.length, str('=poll-test'), str('t'));
  assert.equal(status, lua.LUA_OK, status ? to_jsstring(lua.lua_tostring(L, -1)) : '');
  assert.equal(lua.lua_pcall(L, 0, 8, 0), lua.LUA_OK);
  const result=[];
  for (let i=8; i>=1; i--) result.push(lua.lua_tonumber(L,-i));
  const ok = lua.lua_toboolean(L, -8);
  let selected = '';
  if (ok) selected = to_jsstring(lua.lua_tolstring(L,-7));
  const metrics = result.slice(2);
  lua.lua_close(L);
  return {ok, selected, metrics};
}
const run = (ready, later=[]) => runScenario(implementation, ready, later);
const selectedIndices = Array.from({length:18}, (_, i) => i).join(',');
const readyFirst = {}; for (let i=1;i<=18;i++) readyFirst[i]=1;
let result = run(readyFirst);
assert.equal(result.ok, true);
assert.equal(result.selected, selectedIndices);
assert.deepEqual(result.metrics, [2, 26, 0, 2, 26, 1],
  'ready requests should be selected in order using two batched polls');
const staged = {}; for (let i=1;i<=10;i++) staged[i]=1;
result = run(staged, Array.from({length:8}, (_, i) => i+11));
assert.equal(result.ok, true);
assert.equal(result.selected, selectedIndices);
assert.deepEqual(result.metrics, [3, 42, 1, 3, 42, 2],
  'later passes should poll only the remaining requests after sleeping');
result = run({});
assert.equal(result.ok, false);
assert.deepEqual(result.metrics, [300, 3900, 150, 300, 3900, 150],
  'polling should stop after 150 unsuccessful passes');
console.log('Relapse batched poll behavior tests passed');
