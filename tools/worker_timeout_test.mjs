import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
// Exercise the actual completion wait with a deterministic worker and timer clock.
const source = readFileSync(new URL('../src/main.js',import.meta.url),'utf8');
const start = source.indexOf('    const completed = await new Promise');
const end = source.indexOf('\n    if (!completed)',start);
assert(start >= 0 && end > start);
const timers = new Map();
let next = 0;
const worker = {postMessage:()=>{}};
const context = vm.createContext({worker, timing: null, ROP_WAIT_MS:20000,
  setTimeout: fn => {const id=++next;timers.set(id,fn);return id;},
  clearTimeout: id=>timers.delete(id),
});
const wait = vm.runInContext('(async()=>{'+source.slice(start,end)+';return completed;})',context);
for(let i=0;i<1000;i++) {
  const result=wait();
  assert.equal(timers.size,1);
  worker.onmessage();
  assert.equal(await result,true);
  assert.equal(timers.size,0);
}
const timedOut=wait();
const expire=[...timers.values()][0];
expire();
assert.equal(await timedOut,false);
worker.onmessage();
assert.equal(timers.size,0);
console.log('Worker timeout cleanup tests passed');
