// Regression coverage for synthetic factory faults and VM error attribution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../..');
const bundle = fs.readFileSync(path.join(root, 'src/lua-vm.js'), 'utf8');
const code = bundle.slice(0, bundle.lastIndexOf('\nexport async function run('));

(async () => {
  const normal = vm.createContext({ TextEncoder, TextDecoder });
  vm.runInContext(code, normal, { filename: 'lua-vm.js' });
  const lines = [];
  await normal.WkrlLua.run({ args: [], log: async s => lines.push(s) }, 'print("hello")', '=probe.lua');
  assert.deepEqual(lines, ['hello']);
  console.log('PASS: unchanged runtime initializes and executes hello');

  // Deliberately make .from return bytes belonging to another realm.
  const broken = vm.createContext({ foreignFrom: Uint8Array.from.bind(Uint8Array), foreignOf: Uint8Array.of.bind(Uint8Array) });
  vm.runInContext('Uint8Array.from = foreignFrom; Uint8Array.of = foreignOf', broken);
  vm.runInContext(code, broken, { filename: 'lua-vm.js' });
  const recovered = [];
  await broken.WkrlLua.run({ args: [], log: async s => recovered.push(s) },
    'print("hello", "zażółć 🌙", string.byte("a\\0b", 2))', '=probe.lua');
  assert.deepEqual(recovered, ['hello\tzażółć 🌙\t0']);
  console.log('PASS: foreign byte-array factory no longer breaks initialization or strings');

  const loader = fs.readFileSync(path.join(root, 'src/loader.js'), 'utf8');
  const start = loader.indexOf('function findPayloadLocation(');
  const end = loader.indexOf('\nfunction formatStackFrames(', start);
  const findLocation = vm.runInNewContext('(' + loader.slice(start, end).trim() + ')');
  const payload = fs.readFileSync(path.join(root, 'payloads/lua/relapse.lua'), 'utf8');
  const location = findLocation({ message: 'assertion failed', line: 56, column: 767,
    sourceURL: 'http://127.0.0.1:18181/src/lua-vm.js',
    stack: 'Lf@http://127.0.0.1:18181/src/lua-vm.js:56:767' }, payload);
  assert.equal(location, null);
  const realPayload = findLocation({ line: 56, column: 767,
    sourceURL: 'payload.js', stack: '' }, payload);
  assert.equal(realPayload.line, 55);
  assert.equal(realPayload.col, 767);
  console.log('PASS: VM errors are not attributed to Lua source; real JS payload locations survive');

})().catch(e => { console.error(e); process.exitCode = 1; });
