// Unit test for payloads/sysinfo.js with mock syscalls and sysctl emulation.
// Run: node tools/sysinfo_test.js

import assert from "node:assert/strict";
import fs from "node:fs";
import { int64 } from "../src/utils/int64.js";

const source = fs.readFileSync(new URL("../payloads/sysinfo.js", import.meta.url), "utf8");
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

function writeDirent(buffer, offset, name, type) {
  const namlen = Buffer.byteLength(name);
  const reclen = Math.ceil((8 + namlen + 1) / 8) * 8; // 8-byte aligned
  buffer.writeUInt32LE(1, offset);
  buffer.writeUInt16LE(reclen, offset + 4);
  buffer.writeUInt8(type, offset + 6);
  buffer.writeUInt8(namlen, offset + 7);
  buffer.write(name, offset + 8, "utf8");
  buffer.writeUInt8(0, offset + 8 + namlen);
  return reclen;
}

function createMockApi(options = {}) {
  const logs = [];
  const openFds = new Map(); // fd -> { path, readCount }
  let nextFd = 10;

  const sysctls = {
    "kern.ostype": { type: "string", value: "FreeBSD" },
    "kern.osrelease": { type: "string", value: "11.0-CURRENT" },
    "hw.model": { type: "string", value: "AMD Custom APU" },
    "hw.ncpu": { type: "int32", value: 16 },
    "hw.physmem": { type: "int64", value: 17179869184n }, // 16 GB
  };

  const directoryTree = options.tree ?? {
    "/": [
      { name: "av_contents", type: 4 },
      { name: "dev", type: 4 },
      { name: "system_tmp", type: 4 },
      { name: "user", type: 4 },
    ],
    "/custom/test/path": [
      { name: "file.txt", type: 8 },
      { name: "subdir", type: 4 },
    ],
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
      // SYS_GETPID = 0x014
      if (num === 0x014) return ok(options.pid ?? 1234);
      // SYS_GETPPID = 0x027
      if (num === 0x027) return ok(options.ppid ?? 1);
      // SYS_GETUID = 0x018
      if (num === 0x018) return ok(options.uid ?? 0);
      // SYS_GETEUID = 0x019
      if (num === 0x019) return ok(options.euid ?? 0);
      // SYS_GETGID = 0x02F
      if (num === 0x02f) return ok(options.gid ?? 0);
      // SYS_GETEGID = 0x02B
      if (num === 0x02b) return ok(options.egid ?? 0);
      // SYS_IS_IN_SANDBOX = 0x249
      if (num === 0x249) return ok(options.sandbox ?? 0);

      // SYS_OPEN = 0x005
      if (num === 0x005) {
        const [pathPtr] = args;
        const nullIdx = pathPtr.buffer.indexOf(0, pathPtr.low);
        const path = pathPtr.buffer.toString("utf8", pathPtr.low, nullIdx === -1 ? undefined : nullIdx);
        if (directoryTree[path]) {
          const fd = nextFd++;
          openFds.set(fd, { path, readCount: 0 });
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

      // SYS_GETDENTS = 0x110 (272) or SYS_GETDIRENTRIES = 0x0C4 (196)
      if (num === 0x110 || num === 0x0c4) {
        const [fd, buf, size] = args;
        const state = openFds.get(fd.low);
        if (!state) return failure();
        if (state.readCount > 0) return ok(0); // EOF
        state.readCount++;

        const entries = directoryTree[state.path] || [];
        let offset = buf.low;
        for (const item of entries) {
          offset += writeDirent(buf.buffer, offset, item.name, item.type);
        }
        return ok(offset - buf.low);
      }

      // SYS_NETGETIFLIST = 0x07D
      if (num === 0x07d) {
        const [buf, count] = args;
        if (buf === 0) return ok(1); // count probe
        // Populate one interface: eth0 (192.168.1.133)
        const RECORD = 0x3c0;
        buf.buffer.fill(0, buf.low, buf.low + RECORD * count);
        buf.buffer.write("eth0", buf.low, "utf8");
        buf.buffer.writeUInt8(192, buf.low + 40);
        buf.buffer.writeUInt8(168, buf.low + 41);
        buf.buffer.writeUInt8(1, buf.low + 42);
        buf.buffer.writeUInt8(133, buf.low + 43);
        return ok(0);
      }

      // SYS___SYSCTL = 0x0CA
      if (num === 0x0ca) {
        const [namePtr, namelen, oldPtr, oldLenPtr, newPtr, newlen] = args;
        const mib0 = namePtr.buffer.readUInt32LE(namePtr.low);
        const mib1 = namePtr.buffer.readUInt32LE(namePtr.low + 4);

        // name to MIB lookup: [0, 3]
        if (namelen === 2 && mib0 === 0 && mib1 === 3) {
          const name = newPtr.buffer.toString("utf8", newPtr.low, newPtr.low + newlen);
          if (sysctls[name]) {
            oldPtr.buffer.writeUInt32LE(1, oldPtr.low);
            oldPtr.buffer.writeUInt32LE(100, oldPtr.low + 4); // dummy MIB [1, 100]
            oldLenPtr.buffer.writeUInt32LE(8, oldLenPtr.low);
            oldPtr.buffer.sysctlTarget = name;
            return ok(0);
          }
          return failure();
        }

        // MIB query: [1, 100]
        const target = oldPtr.buffer.sysctlTarget;
        if (target && sysctls[target]) {
          const entry = sysctls[target];
          if (entry.type === "string") {
            const bytes = Buffer.from(entry.value, "utf8");
            bytes.copy(oldPtr.buffer, oldPtr.low);
            oldPtr.buffer.writeUInt8(0, oldPtr.low + bytes.length);
            oldLenPtr.buffer.writeUInt32LE(bytes.length + 1, oldLenPtr.low);
            return ok(0);
          }
          if (entry.type === "int32") {
            oldPtr.buffer.writeUInt32LE(entry.value >>> 0, oldPtr.low);
            oldLenPtr.buffer.writeUInt32LE(4, oldLenPtr.low);
            return ok(0);
          }
          if (entry.type === "int64") {
            oldPtr.buffer.writeBigUInt64LE(entry.value, oldPtr.low);
            oldLenPtr.buffer.writeUInt32LE(8, oldLenPtr.low);
            return ok(0);
          }
        }
        return failure();
      }

      return failure();
    },
  };

  return {
    api: {
      p,
      chain,
      fw: options.fw ?? "4.03",
      krw: options.krw !== undefined ? options.krw : true,
      args: options.args ?? [],
      libKernelBase: new int64(0x80010000, 0x8),
      libSceNKWebKitBase: new int64(0x82000000, 0x8),
      libSceLibcInternalBase: new int64(0x84000000, 0x8),
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

// Test 1: Full diagnostic run with default arguments (lists root /)
{
  const mock = createMockApi();
  await entry(mock.api);

  assert.equal(mock.getOpenFds().size, 0, "all fds must be closed");
  const logs = mock.getLogs().map((l) => l.msg);

  assert(logs.some((l) => l.includes("Firmware:       4.03")));
  assert(logs.some((l) => l.includes("Kernel R/W:     established (active)")));
  assert(logs.some((l) => l.includes("OS:             FreeBSD 11.0-CURRENT")));
  assert(logs.some((l) => l.includes("Hardware:       AMD Custom APU")));
  assert(logs.some((l) => l.includes("CPU Cores:      16")));
  assert(logs.some((l) => l.includes("Physical RAM:   16384 MB")));
  assert(logs.some((l) => l.includes("PID / PPID:     1234 / 1")));
  assert(logs.some((l) => l.includes("UID / EUID:     0 (root) / 0")));
  assert(logs.some((l) => l.includes("Sandbox:        escaped (unsandboxed)")));
  assert(logs.some((l) => l.includes("libkernel:      0x880010000")));
  assert(logs.some((l) => l.includes("eth0:        192.168.1.133")));

  // Directory listing checks for /
  assert(logs.some((l) => l.includes("=== Directory Listing: / ===")));
  assert(logs.some((l) => l.includes("av_contents/             [dir]")));
  assert(logs.some((l) => l.includes("dev/                     [dir]")));
  assert(logs.some((l) => l.includes("system_tmp/              [dir]")));
  assert(logs.some((l) => l.includes("user/                    [dir]")));

  console.log("ok   sysinfo.js reports full diagnostics and dynamic root directory contents");
}

// Test 2: Sandboxed process and custom directory argument
{
  const mock = createMockApi({
    sandbox: 1,
    uid: 1000,
    euid: 1000,
    krw: null,
    args: ["/custom/test/path"],
  });
  await entry(mock.api);

  const logs = mock.getLogs().map((l) => l.msg);
  assert(logs.some((l) => l.includes("Kernel R/W:     not established")));
  assert(logs.some((l) => l.includes("UID / EUID:     1000 / 1000")));
  assert(logs.some((l) => l.includes("Sandbox:        active (restricted)")));

  // Directory listing for custom path
  assert(logs.some((l) => l.includes("=== Directory Listing: /custom/test/path ===")));
  assert(logs.some((l) => l.includes("file.txt                 [file]")));
  assert(logs.some((l) => l.includes("subdir/                  [dir]")));

  console.log("ok   sysinfo.js lists custom directories requested in argv");
}

console.log("\nAll sysinfo_test.js checks passed.");
