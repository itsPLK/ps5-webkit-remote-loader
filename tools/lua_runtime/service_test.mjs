import assert from 'node:assert/strict';
import {run} from '../../src/lua-vm.js';
import {int64} from '../../src/utils/int64.js';
const events = [];
let releaseCall, reachedCall;
const started = new Promise(resolve => { reachedCall = resolve; });
const gate = new Promise(resolve => { releaseCall = resolve; });
const api = {
  args:['service=1'], int64,
  setPayloadTimeout: value => events.push(['timeout',value]),
  log: async line => { events.push(['log',line]); },
  chain:{syscall:async n=>{
    events.push(['syscall',n]); reachedCall(); await gate; return new int64(77);
  }},
};
const running = run(api,'print("listening"); syscall.getpid(); print("done")');
await started;
assert.deepEqual(events,[['timeout',0],['log','listening'],['syscall',20]]);
releaseCall(); await running;
assert.deepEqual(events.at(-1),['log','done']);
const quiet = {...api,log:async()=>{},chain:{syscall:async()=>new int64(77)}};
const work = 'for j=1,16 do local n=0; for i=1,60000 do n=n+i end; syscall.getpid() end';
await run(quiet,work);
await assert.rejects(run({...quiet,args:[]},work),/instruction budget/);
await assert.rejects(run(quiet,'while true do end'),/instruction budget/);
await assert.rejects(run(quiet,'print(string.rep("x",1048577))'),/output budget/);
await run(quiet,'for i=1,20 do print(string.rep("x",65536)) end');
await assert.rejects(run({...quiet,args:[]},'for i=1,20 do print(string.rep("x",65536)) end'),/output budget/);
await assert.rejects(run({...quiet,log:async()=>{throw Error('sink failed');}},'print("x")'),/sink failed/);
await run({...quiet,log:async()=>{throw Error('sink failed');}},'local ok,err=pcall(print,"x"); assert(not ok and string.find(err,"sink failed"))');
const noTimeout = {...quiet,setPayloadTimeout:()=>{throw Error('timeout must not change');}};
await run({...noTimeout,args:[]},'print("ordinary")');
await assert.rejects(run(noTimeout,'local ='),/payload.lua/);
await run({...quiet,args:['service=1','compat=remote_lua_loader']},'printf("pid %d",syscall.getpid():tonumber())');
await run(quiet,'local ok,err=coroutine.resume(coroutine.create(function() print("child") end)); assert(not ok and string.find(err,"main Lua coroutine"))');
console.log('Lua service policy tests passed');
