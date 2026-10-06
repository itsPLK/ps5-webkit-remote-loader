// Unit test for payloads/readfile.js with mock syscalls.
// Run: node tools/readfile_test.js

import assert from "node:assert/strict";
import fs from "node:fs";
import { int64 } from "../src/utils/int64.js";

const source = fs.readFileSync(new URL("../payloads/readfile.js", import.meta.url), "utf8");
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

  const files = options.files ?? {
    "/user/trophy.ini": Buffer.from("TROPSYSVER=1.0\r\nTROPTITLEID=NPWR06221_00\r\n", "utf8"),
    "/etc/hosts": Buffer.from("127.0.0.1 localhost\n", "utf8"),
  };

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
    read1(a) {
      return a.buffer.readUInt8(a.low);
    },
  };

  const chain = {
    async syscall(num, ...args) {
      // SYS_OPEN = 0x005
      if (num === 0x005) {
        if (options.failOpen) return failure();
        const [pathPtr] = args;
        const nullIdx = pathPtr.buffer.indexOf(0, pathPtr.low);
        const path = pathPtr.buffer.toString("utf8", pathPtr.low, nullIdx === -1 ? undefined : nullIdx);
        if (files[path]) {
          const fd = nextFd++;
          openFds.set(fd, { path, offset: 0 });
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

      // SYS_LSEEK = 0x1DE
      if (num === 0x1de) {
        const [fd, offsetVal] = args;
        const state = openFds.get(fd.low);
        if (!state) return failure();
        state.offset = offsetVal.low;
        return ok(state.offset);
      }

      // SYS_READ = 0x003
      if (num === 0x003) {
        const [fd, buf, size] = args;
        const state = openFds.get(fd.low);
        if (!state) return failure();
        const fileBuf = files[state.path];
        if (state.offset >= fileBuf.length) return ok(0); // EOF
        const want = Math.min(size, fileBuf.length - state.offset);
        fileBuf.copy(buf.buffer, buf.low, state.offset, state.offset + want);
        state.offset += want;
        return ok(want);
      }

      return failure();
    },
  };

  return {
    api: {
      p,
      chain,
      int64,
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

// Test 1: Default hexdump mode (split hex + ASCII sidebar)
{
  const mock = createMockApi({ args: ["/user/trophy.ini"] });
  await entry(mock.api);

  assert.equal(mock.getOpenFds().size, 0, "fd should be closed");
  const lines = mock.getLogs().map((l) => l.msg);

  assert(lines.some((l) => l.includes("open(/user/trophy.ini) = fd 10")));
  // Should have format: 00000000  54 52 4f 50 ...  |...|
  const hexLine = lines.find((l) => l.startsWith("00000000  "));
  assert(hexLine, "must output 8-digit hex offset");
  assert(hexLine.includes("|TROPSYSVER=1.0..|"), "must output ASCII sidebar");
  assert(lines.some((l) => l.includes("read 42 bytes of /user/trophy.ini")));

  console.log("ok   readfile.js default hexdump with ASCII sidebar");
}

// Test 2: Plain text mode (--arg text)
{
  const mock = createMockApi({ args: ["text", "/user/trophy.ini"] });
  await entry(mock.api);

  const lines = mock.getLogs().map((l) => l.msg);
  assert(lines.some((l) => l === "TROPSYSVER=1.0"));
  assert(lines.some((l) => l === "TROPTITLEID=NPWR06221_00"));

  console.log("ok   readfile.js text mode");
}

// Test 3: Custom width (--arg width=8)
{
  const mock = createMockApi({ args: ["width=8", "/user/trophy.ini"] });
  await entry(mock.api);

  const lines = mock.getLogs().map((l) => l.msg);
  const row0 = lines.find((l) => l.startsWith("00000000  "));
  const row1 = lines.find((l) => l.startsWith("00000008  "));
  assert(row0 && row1, "must step by 8 with width=8");
  assert(row0.includes("|TROPSYSV|"));

  console.log("ok   readfile.js custom width");
}

// Test 4: Hex-only mode (--arg hex)
{
  const mock = createMockApi({ args: ["hex", "/user/trophy.ini"] });
  await entry(mock.api);

  const lines = mock.getLogs().map((l) => l.msg);
  const hexLine = lines.find((l) => l.startsWith("00000000  "));
  assert(hexLine);
  assert(!hexLine.includes("|"), "hex-only mode must not include ASCII bar");

  console.log("ok   readfile.js hex-only mode");
}

// Test 5: Offset and limit
{
  const mock = createMockApi({ args: ["offset=16", "limit=10", "text", "/user/trophy.ini"] });
  await entry(mock.api);

  const lines = mock.getLogs().map((l) => l.msg);
  assert(lines.some((l) => l.includes("read 10 bytes of /user/trophy.ini")));

  console.log("ok   readfile.js offset and limit");
}

console.log("\nAll readfile_test.js checks passed.");
