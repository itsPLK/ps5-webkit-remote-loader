// Unit test for payloads/notify.js with mock syscalls.
// Run: node tools/notify_test.js

import assert from "node:assert/strict";
import fs from "node:fs";
import { int64 } from "../src/utils/int64.js";

const source = fs.readFileSync(new URL("../payloads/notify.js", import.meta.url), "utf8");
const entry = new Function(source)();

const ok = (n = 0) => new int64(n >>> 0, Math.floor(n / 0x100000000));
const failure = () => new int64(0xffffffff, 0xffffffff);

function pointer(buffer, offset = 0) {
  return {
    buffer,
    low: offset,
    hi: 0,
    add32(n) {
      return pointer(buffer, offset + n);
    },
  };
}

function createMockApi(options = {}) {
  const logs = [];
  const syscallHistory = [];
  const openFds = new Set();
  let nextFd = 10;
  let lastWrittenBuffer = null;

  const p = {
    malloc(size, type) {
      assert.equal(type, 1);
      return pointer(Buffer.alloc(size + 1000));
    },
    stringify(str) {
      const buf = Buffer.alloc(str.length + 1);
      buf.write(str, "utf8");
      return pointer(buf);
    },
    write1(a, n) {
      a.buffer.writeUInt8(n & 0xff, a.low);
    },
    write4(a, n) {
      a.buffer.writeUInt32LE(n >>> 0, a.low);
    },
    read1(a) {
      return a.buffer.readUInt8(a.low);
    },
    read4(a) {
      return a.buffer.readUInt32LE(a.low);
    },
  };

  const chain = {
    async syscall(num, ...args) {
      syscallHistory.push({ num, args });
      // SYS_OPEN = 5
      if (num === 0x005) {
        if (options.failOpen) return failure();
        const fd = nextFd++;
        openFds.add(fd);
        return ok(fd);
      }
      // SYS_WRITE = 4
      if (num === 0x004) {
        if (options.failWrite) return failure();
        const [fd, buf, size] = args;
        assert(openFds.has(fd.low));
        lastWrittenBuffer = Buffer.from(buf.buffer.subarray(buf.low, buf.low + size));
        return ok(size);
      }
      // SYS_CLOSE = 6
      if (num === 0x006) {
        const [fd] = args;
        openFds.delete(fd.low);
        return ok(0);
      }
      return failure();
    },
  };

  return {
    api: {
      p,
      chain,
      args: options.args || [],
      isFailure: (n) => (n.low === 0xffffffff && n.hi === 0xffffffff) || (n.low | 0) < 0,
      describe: (n) => `0x${(n.low >>> 0).toString(16)}`,
      async log(msg, type = "info") {
        logs.push({ msg, type });
      },
    },
    getLogs: () => logs,
    getSyscalls: () => syscallHistory,
    getOpenFds: () => openFds,
    getLastWrittenBuffer: () => lastWrittenBuffer,
  };
}

function readCString(buf, offset) {
  const nullIdx = buf.indexOf(0, offset);
  if (nullIdx === -1) return buf.toString("utf8", offset);
  return buf.toString("utf8", offset, nullIdx);
}

// Test 1: Default message when no args provided
{
  const mock = createMockApi({ args: [] });
  await entry(mock.api);

  assert.equal(mock.getOpenFds().size, 0, "all fds should be closed");
  const syscalls = mock.getSyscalls();
  assert.equal(syscalls.length, 3);
  assert.equal(syscalls[0].num, 5, "SYS_OPEN");
  assert.equal(syscalls[1].num, 4, "SYS_WRITE");
  assert.equal(syscalls[1].args[2], 0xc30, "size must be 0xc30 (3120 bytes)");
  assert.equal(syscalls[2].num, 6, "SYS_CLOSE");

  const written = mock.getLastWrittenBuffer();
  assert.equal(written.length, 0xc30);
  assert.equal(written.readUInt32LE(0x00), 0, "type == 0");
  assert.equal(written.readUInt32LE(0x10), 0xffffffff, "target_id == -1");
  assert.equal(written.readUInt8(0x2c), 1, "use_icon_image_uri == 1");
  assert.equal(readCString(written, 0x2d), "Hello from WebKit Remote Loader!");
  assert.equal(readCString(written, 0x42d), "cxml://psnotification/tex_icon_system");

  const logs = mock.getLogs();
  assert.equal(logs.length, 1);
  assert.equal(logs[0].type, "success");
  assert.match(logs[0].msg, /Hello from WebKit Remote Loader!/);
  console.log("ok   notify.js default message");
}

// Test 2: Custom message from argv
{
  const mock = createMockApi({ args: ["Kernel", "exploit", "stage", "1", "passed!"] });
  await entry(mock.api);

  const written = mock.getLastWrittenBuffer();
  assert.equal(readCString(written, 0x2d), "Kernel exploit stage 1 passed!");
  assert.equal(readCString(written, 0x42d), "cxml://psnotification/tex_icon_system");

  const logs = mock.getLogs();
  assert.equal(logs.length, 1);
  assert.equal(logs[0].type, "success");
  assert.match(logs[0].msg, /Kernel exploit stage 1 passed!/);
  console.log("ok   notify.js custom argv message");
}

// Test 3: Failure on open
{
  const mock = createMockApi({ failOpen: true });
  await entry(mock.api);

  const syscalls = mock.getSyscalls();
  assert.equal(syscalls.length, 1, "only SYS_OPEN should have been called");
  assert.equal(syscalls[0].num, 5);

  const logs = mock.getLogs();
  assert.equal(logs.length, 1);
  assert.equal(logs[0].type, "error");
  assert.match(logs[0].msg, /open\(\/dev\/notification0\) failed/);
  console.log("ok   notify.js handles open failure");
}

// Test 4: Failure on write closes fd and logs error
{
  const mock = createMockApi({ failWrite: true });
  await entry(mock.api);

  assert.equal(mock.getOpenFds().size, 0, "fd should still be closed after write failure");
  const syscalls = mock.getSyscalls();
  assert.equal(syscalls.length, 3);
  assert.equal(syscalls[0].num, 5, "SYS_OPEN");
  assert.equal(syscalls[1].num, 4, "SYS_WRITE");
  assert.equal(syscalls[2].num, 6, "SYS_CLOSE");

  const logs = mock.getLogs();
  assert.equal(logs.length, 1);
  assert.equal(logs[0].type, "error");
  assert.match(logs[0].msg, /write\(\/dev\/notification0\) failed/);
  console.log("ok   notify.js handles write failure with clean close");
}

console.log("\nAll notify_test.js checks passed.");
