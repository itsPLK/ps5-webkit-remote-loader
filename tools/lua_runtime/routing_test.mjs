import assert from 'node:assert/strict';
import { executePayload } from '../../src/loader.js';
import { int64 } from '../../src/utils/int64.js';

async function run(code) {
  const lines = [];
  const log = async message => lines.push(message);
  const result = await executePayload({code, size: new TextEncoder().encode(code).length,
    api: {args: [], log, int64, chain: {syscall: async number => {
      assert.equal(number,20);
      return new int64(77);
    }}}, log, say: log, servedCount: 1});
  return {result, lines};
}
for (const header of ['--!lua\n','--lua\n','--!lua\r\n','\uFEFF--!lua\n']) {
  const {result, lines} = await run(header + 'print("pid", syscall.getpid())');
  assert.equal(result.failed, false);
  assert(lines.includes('pid\t0x4d'));
}
assert.equal((await run('--!lua\nerror("Lua failure")')).result.failed, true);
assert.equal((await run('--!lua\nlocal =')).result.failed, true);
assert((await run('--!lua\nprint("recovered")')).lines.includes('recovered'));
assert((await run('return async api => { await api.log("JS works"); };')).lines.includes('JS works'));
for (const header of ['--!luau\n','--lua extra\n',' --!lua\n']) {
  assert.equal((await run(header + 'print("wrong route")')).result.failed, true);
}
console.log('Lua payload routing tests passed');
