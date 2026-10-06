// Unit test for payloads/klog.js with mock syscalls.
// Run: node tools/klog_test.js

import assert from "node:assert/strict";
import fs from "node:fs";
import { int64 } from "../src/utils/int64.js";

const source = fs.readFileSync(new URL("../payloads/klog.js", import.meta.url), "utf8");
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
  const openFds = new Map();
  let nextFd = 10;

  const mockKlogData = options.klogData ?? [
    "<6>FreeBSD 11.0-CURRENT kernel initialized\n<6>ps5: cpu0 initialized\n",
    "<4>warning: device attach deferred\n<3>error: sflash signature verify skipped\n",
  ];

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
    write2(a, n) {
      a.buffer.writeUInt16LE(n & 0xffff, a.low);
    },
    write4(a, n) {
      a.buffer.writeUInt32LE(n >>> 0, a.low);
    },
    read1(a) {
      return a.buffer.readUInt8(a.low);
    },
    read2(a) {
      return a.buffer.readUInt16LE(a.low);
    },
    read4(a) {
      return a.buffer.readUInt32LE(a.low);
    },
  };

  const chain = {
    async syscall(num, ...args) {
      // SYS_GETUID = 0x018
      if (num === 0x018) return ok(options.uid ?? 0);

      // SYS_OPEN = 0x005
      if (num === 0x005) {
        if (options.failOpen) return failure();
        const [pathPtr, flags] = args;
        const nullIdx = pathPtr.buffer.indexOf(0, pathPtr.low);
        const path = pathPtr.buffer.toString("utf8", pathPtr.low, nullIdx === -1 ? undefined : nullIdx);
        if (path === "/dev/klog") {
          const fd = nextFd++;
          openFds.set(fd, { chunkIndex: 0 });
          return ok(fd);
        }
        return failure();
      }

      // SYS_CLOSE = 0x006
      if (num === 0x006) {
        const [fd] = args;
        openFds.delete(fd.low);
        return ok(0);
      }

      // SYS_POLL = 0x0D1
      if (num === 0x0d1) {
        const [pollfdPtr, nfds, timeout] = args;
        const fd = pollfdPtr.buffer.readUInt32LE(pollfdPtr.low);
        const state = openFds.get(fd);
        if (!state) return failure();
        if (state.chunkIndex < mockKlogData.length) {
          // Data ready to read
          pollfdPtr.buffer.writeUInt16LE(1, pollfdPtr.low + 6); // POLLIN
          return ok(1);
        }
        // Buffer drained (timeout)
        pollfdPtr.buffer.writeUInt16LE(0, pollfdPtr.low + 6);
        return ok(0);
      }

      // SYS_READ = 0x003
      if (num === 0x003) {
        const [fd, buf, size] = args;
        const state = openFds.get(fd.low);
        if (!state || state.chunkIndex >= mockKlogData.length) return ok(0);
        const text = mockKlogData[state.chunkIndex++];
        const bytes = Buffer.from(text, "utf8");
        bytes.copy(buf.buffer, buf.low);
        return ok(bytes.length);
      }

      return failure();
    },
  };

  return {
    api: {
      p,
      chain,
      krw: options.krw ?? true,
      args: options.args ?? [],
      isFailure: (n) => (n.low === 0xffffffff && n.hi === 0xffffffff) || (n.low | 0) < 0,
      describe: (n) => `0x${(n.low >>> 0).toString(16)}`,
      async log(msg, type = "info") {
        logs.push({ msg, type });
      },
    },
    getLogs: () => logs,
    getOpenFds: () => openFds,
  };
}

// Test 1: Snapshot mode drains ring buffer, strips syslog tags, and closes fd
{
  const mock = createMockApi();
  await entry(mock.api);

  assert.equal(mock.getOpenFds().size, 0, "fd should be closed");
  const lines = mock.getLogs().map((l) => l.msg);

  assert(lines.some((l) => l.includes("=== Kernel Log (dmesg snapshot) ===")));
  assert(lines.some((l) => l === "FreeBSD 11.0-CURRENT kernel initialized"));
  assert(lines.some((l) => l === "ps5: cpu0 initialized"));
  assert(lines.some((l) => l === "warning: device attach deferred"));
  assert(lines.some((l) => l === "error: sflash signature verify skipped"));
  assert(lines.some((l) => l.includes("=== End of Kernel Log (4 lines")));

  console.log("ok   klog.js snapshot mode drains messages and strips syslog tags");
}

// Test 2: Filter option (--arg grep=sflash)
{
  const mock = createMockApi({ args: ["grep=sflash"] });
  await entry(mock.api);

  const lines = mock.getLogs().map((l) => l.msg);
  assert(lines.some((l) => l === "error: sflash signature verify skipped"));
  assert(!lines.some((l) => l === "ps5: cpu0 initialized"));

  console.log("ok   klog.js filters lines with grep argument");
}

// Test 3: Raw mode keeps syslog tags
{
  const mock = createMockApi({ args: ["raw"] });
  await entry(mock.api);

  const lines = mock.getLogs().map((l) => l.msg);
  assert(lines.some((l) => l === "<6>FreeBSD 11.0-CURRENT kernel initialized"));
  assert(lines.some((l) => l === "<3>error: sflash signature verify skipped"));

  console.log("ok   klog.js retains raw tags with raw argument");
}

// Test 4: Open failure when not root
{
  const mock = createMockApi({ failOpen: true, uid: 1, krw: false });
  await entry(mock.api);

  const logs = mock.getLogs();
  assert(logs.some((l) => l.type === "warn" && l.msg.includes("requires root privileges")));
  assert(logs.some((l) => l.type === "error" && l.msg.includes("open(/dev/klog) failed")));

  console.log("ok   klog.js handles permission failure gracefully");
}

console.log("\nAll klog_test.js checks passed.");
