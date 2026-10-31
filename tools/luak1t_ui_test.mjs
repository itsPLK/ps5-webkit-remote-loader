import assert from 'node:assert/strict';
import { executePayload } from '../src/loader.js';
import { int64 } from '../src/utils/int64.js';

// Setup minimal mock DOM
function createMockElement(tag, className = '') {
  return {
    tagName: tag.toUpperCase(),
    className,
    textContent: '',
    childNodes: [],
    style: {},
    appendChild(child) {
      this.childNodes.push(child);
      return child;
    },
    removeChild(child) {
      const idx = this.childNodes.indexOf(child);
      if (idx >= 0) this.childNodes.splice(idx, 1);
      return child;
    },
    get lastElementChild() {
      return this.childNodes[this.childNodes.length - 1] || null;
    },
  };
}

const consoleEl = createMockElement('div');
globalThis.document = {
  getElementById: (id) => (id === 'console' ? consoleEl : null),
  createElement: (tag) => createMockElement(tag),
};
globalThis.window = globalThis;
globalThis.output = consoleEl;
globalThis.scrollTo = () => {};
globalThis.addEventListener = () => {};
globalThis.removeEventListener = () => {};
Object.defineProperty(globalThis, 'navigator', {
  value: { userAgent: 'test-agent' },
  configurable: true,
  writable: true,
});

// Import site.js to register writeLog and startLogBox
await import('../src/site.js');

assert.equal(typeof window.writeLog, 'function', 'writeLog should be defined on window');
assert.equal(typeof window.startLogBox, 'function', 'startLogBox should be defined on window');
assert.equal(typeof window.endLogBox, 'function', 'endLogBox should be defined on window');

consoleEl.childNodes = [];

// Test 1: Run Lua payload and verify LuaK1t box is created with header, badge, and content
{
  const luaCode = '--!lua\nprint("Hello from Lua")';
  const lines = [];
  const log = async (msg, type) => {
    lines.push(msg);
    window.writeLog(msg, type);
  };

  const res = await executePayload({
    code: luaCode,
    size: Buffer.byteLength(luaCode),
    api: { args: [], log, int64, chain: { syscall: async () => new int64(0) } },
    log,
    say: log,
    servedCount: 1,
  });

  assert.equal(res.failed, false, 'Lua execution should succeed');

  // Verify child nodes of console
  const boxes = consoleEl.childNodes.filter(n => n.className === 'luak1t-box');
  assert.equal(boxes.length, 1, 'Exactly one luak1t-box should be added to the console');

  const box = boxes[0];
  const header = box.childNodes.find(n => n.className === 'luak1t-header');
  assert.ok(header, 'luak1t-box must have a luak1t-header');

  const badge = header.childNodes.find(n => n.className === 'luak1t-badge');
  assert.ok(badge, 'luak1t-header must contain a luak1t-badge');
  assert.equal(badge.textContent, 'Lua', 'Badge text must be "Lua"');

  const content = box.childNodes.find(n => n.className === 'luak1t-content');
  assert.ok(content, 'luak1t-box must contain a luak1t-content container');

  const contentLines = content.childNodes.map(n => n.textContent);
  assert(contentLines.some(l => l.includes('Hello from Lua')), 'Lua print output must be inside luak1t-content');

  // Outside logs (like --- payload done ---) must be on consoleEl, not inside content
  const outsideLines = consoleEl.childNodes.filter(n => n.className && n.className.startsWith('log-line')).map(n => n.textContent);
  assert(outsideLines.some(l => l.includes('payload done')), 'payload done banner must be outside the box');
}

// Test 2: Run JavaScript payload and verify NO LuaK1t box is created
{
  consoleEl.childNodes = [];
  const jsCode = 'return async function(api) { await api.log("JS hello"); };';
  const lines = [];
  const log = async (msg, type) => {
    lines.push(msg);
    window.writeLog(msg, type);
  };

  const res = await executePayload({
    code: jsCode,
    size: Buffer.byteLength(jsCode),
    api: { args: [], log, int64, chain: { syscall: async () => new int64(0) } },
    log,
    say: log,
    servedCount: 2,
  });

  assert.equal(res.failed, false, 'JS execution should succeed');
  const boxes = consoleEl.childNodes.filter(n => n.className === 'luak1t-box');
  assert.equal(boxes.length, 0, 'JS payloads must NOT create a luak1t-box');
}

// Test 3: Run Lua payload that throws and verify box closes properly
{
  consoleEl.childNodes = [];
  const luaFailCode = '--!lua\nerror("deliberate test error")';
  const lines = [];
  const log = async (msg, type) => {
    lines.push(msg);
    window.writeLog(msg, type);
  };

  const res = await executePayload({
    code: luaFailCode,
    size: Buffer.byteLength(luaFailCode),
    api: { args: [], log, int64, chain: { syscall: async () => new int64(0) } },
    log,
    say: log,
    servedCount: 3,
  });

  assert.equal(res.failed, true, 'Failing payload should report failed');
  const boxes = consoleEl.childNodes.filter(n => n.className === 'luak1t-box');
  assert.equal(boxes.length, 1, 'Error should still create the box');

  // After completion, write a new line to console and verify it goes to consoleEl, not the box
  window.writeLog('post-lua log', 'info');
  const lastConsoleChild = consoleEl.childNodes[consoleEl.childNodes.length - 1];
  assert(lastConsoleChild.textContent.includes('post-lua log'), 'Subsequent logs must not go into the closed box');
}

console.log('All LuaK1t UI box tests passed successfully!');
