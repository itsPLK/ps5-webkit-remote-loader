// Unit test for payloads/df.js with mock fstatfs / open / close syscalls.
// Run: node tools/df_test.js

import assert from "node:assert/strict";
import fs from "node:fs";
import { int64 } from "../src/utils/int64.js";

const source = fs.readFileSync(new URL("../payloads/df.js", import.meta.url), "utf8");
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

const DEFAULT_MOUNTS = [
  {
    path: "/",
    filesystem: "/dev/ssd0.0",
    mountedOn: "/",
    type: "ufs",
    bsize: 4096,
    iosize: 65536,
    totalBlocks: 2621440,       // 10.0 GB
    freeBlocks: 1048576,        // 4.0 GB free
    availBlocks: 786432,        // 3.0 GB avail
    totalInodes: 1000000,
    freeInodes: 850000,
    flags: 0x00004001,          // MNT_ROOTFS | MNT_RDONLY
  },
  {
    path: "/data",
    filesystem: "/dev/ssd0.0.1",
    mountedOn: "/data",
    type: "ufs",
    bsize: 4096,
    iosize: 65536,
    totalBlocks: 174850048,     // ~667.0 GB
    freeBlocks: 142147584,      // ~542.2 GB free
    availBlocks: 142147584,
    totalInodes: 5000000,
    freeInodes: 4500000,
    flags: 0x00001000,          // MNT_LOCAL
  },
  {
    path: "/user",
    filesystem: "/dev/ssd0.0.2",
    mountedOn: "/user",
    type: "ufs",
    bsize: 4096,
    iosize: 65536,
    totalBlocks: 26214400,      // 100.0 GB
    freeBlocks: 15728640,       // 60.0 GB free
    availBlocks: 14417920,      // 55.0 GB avail
    totalInodes: 2000000,
    freeInodes: 1800000,
    flags: 0x00001040,          // MNT_LOCAL | MNT_ASYNC
  },
  {
    path: "/dev",
    filesystem: "devfs",
    mountedOn: "/dev",
    type: "devfs",
    bsize: 512,
    iosize: 512,
    totalBlocks: 2,             // 1 KB
    freeBlocks: 0,
    availBlocks: 0,
    totalInodes: 0,
    freeInodes: 0,
    flags: 0x00001000,          // MNT_LOCAL
  },
  {
    path: "/mnt/usb0",
    filesystem: "/dev/da0s1",
    mountedOn: "/mnt/usb0",
    type: "exfat",
    bsize: 32768,
    iosize: 65536,
    totalBlocks: 3932160,       // 120.0 GB
    freeBlocks: 3276800,        // 100.0 GB free
    availBlocks: 3276800,
    totalInodes: 0,
    freeInodes: 0,
    flags: 0x00001000,          // MNT_LOCAL
  },
];

function createMockApi(options = {}) {
  const logs = [];
  const mounts = options.mounts || DEFAULT_MOUNTS;
  const openedFds = new Map();
  let nextFd = 10;

  const p = {
    malloc(size, type) {
      assert.equal(type, 1);
      return pointer(Buffer.alloc(size + 1024));
    },
    stringify(str) {
      const buf = Buffer.from(str + "\0", "utf8");
      return pointer(buf);
    },
    write4(a, n) {
      a.buffer.writeUInt32LE(n >>> 0, a.low);
    },
    read4(a) {
      return a.buffer.readUInt32LE(a.low);
    },
    read1(a) {
      return a.buffer.readUInt8(a.low);
    },
  };

  const chain = {
    async syscall(num, ...args) {
      // SYS_OPEN = 0x005
      if (num === 0x005) {
        const [pathPtr] = args;
        // Read null-terminated string from buffer
        let path = "";
        let off = pathPtr.low;
        while (off < pathPtr.buffer.length) {
          const byte = pathPtr.buffer.readUInt8(off++);
          if (byte === 0) break;
          path += String.fromCharCode(byte);
        }

        const match = mounts.find(m => m.path === path);
        if (!match) {
          return failure();
        }

        const fd = nextFd++;
        openedFds.set(fd, match);
        return ok(fd);
      }

      // SYS_CLOSE = 0x006
      if (num === 0x006) {
        const [fd] = args;
        openedFds.delete(typeof fd === "number" ? fd : fd.low);
        return ok(0);
      }

      // SYS_FSTATFS = 0x18D
      if (num === 0x18D) {
        if (options.failFstatfs) return failure();

        const [fd, bufPtr] = args;
        const info = openedFds.get(typeof fd === "number" ? fd : fd.low);
        if (!info) return failure();

        const buf = bufPtr.buffer;
        const base = bufPtr.low;

        // Zero out
        buf.fill(0, base, base + 512);

        // f_version (0x00)
        buf.writeUInt32LE(0x20030518, base);
        // f_type (0x04)
        buf.writeUInt32LE(1, base + 4);
        // f_flags (0x08)
        buf.writeUInt32LE(info.flags >>> 0, base + 8);
        buf.writeUInt32LE(0, base + 12);
        // f_bsize (0x10)
        buf.writeUInt32LE(info.bsize >>> 0, base + 16);
        buf.writeUInt32LE(Math.floor(info.bsize / 0x100000000), base + 20);
        // f_iosize (0x18)
        buf.writeUInt32LE(info.iosize >>> 0, base + 24);
        buf.writeUInt32LE(0, base + 28);
        // f_blocks (0x20)
        buf.writeUInt32LE(info.totalBlocks >>> 0, base + 32);
        buf.writeUInt32LE(Math.floor(info.totalBlocks / 0x100000000), base + 36);
        // f_bfree (0x28)
        buf.writeUInt32LE(info.freeBlocks >>> 0, base + 40);
        buf.writeUInt32LE(Math.floor(info.freeBlocks / 0x100000000), base + 44);
        // f_bavail (0x30)
        buf.writeUInt32LE(info.availBlocks >>> 0, base + 48);
        buf.writeUInt32LE(Math.floor(info.availBlocks / 0x100000000), base + 52);
        // f_files (0x38)
        buf.writeUInt32LE(info.totalInodes >>> 0, base + 56);
        buf.writeUInt32LE(Math.floor(info.totalInodes / 0x100000000), base + 60);
        // f_ffree (0x40)
        buf.writeUInt32LE(info.freeInodes >>> 0, base + 64);
        buf.writeUInt32LE(Math.floor(info.freeInodes / 0x100000000), base + 68);

        // f_fstypename (0x118 = 280)
        const typeBuf = Buffer.from(info.type + "\0", "utf8");
        typeBuf.copy(buf, base + 280);

        // f_mntfromname (0x128 = 296)
        const fromBuf = Buffer.from(info.filesystem + "\0", "utf8");
        fromBuf.copy(buf, base + 296);

        // f_mntonname (0x180 = 384)
        const toBuf = Buffer.from(info.mountedOn + "\0", "utf8");
        toBuf.copy(buf, base + 384);

        return ok(0);
      }

      return failure();
    },
  };

  return {
    p,
    chain,
    syscalls: {
      0x005: 0x1000,
      0x006: 0x2000,
      0x18D: options.omitFstatfs ? undefined : 0x3000,
    },
    args: options.args || [],
    isFailure: (v) => !v || v.low === 0xffffffff,
    describe: (v) => `0x${((v?.low ?? 0) >>> 0).toString(16)}`,
    log: async (msg, type) => {
      logs.push({ msg, type: type || "info" });
    },
    getLogs: () => logs,
    openedFds,
  };
}

// Test 1: Default execution discovers mounted partitions
{
  const mock = createMockApi();
  await entry(mock);

  const logs = mock.getLogs();
  assert(logs.some(l => l.msg.includes("filesystems: 5 mounted partition(s) inspected")));
  assert(logs.some(l => l.msg.includes("/data") && l.msg.includes("ufs")));
  assert(logs.some(l => l.msg.includes("/user") && l.msg.includes("ufs")));
  assert(logs.some(l => l.msg.includes("/mnt/usb0") && l.msg.includes("exfat")));

  // All opened file descriptors must be closed
  assert.equal(mock.openedFds.size, 0, "all fds should be closed");
}

// Test 2: Custom path argument (e.g. /data)
{
  const mock = createMockApi({ args: ["/data"] });
  await entry(mock);

  const logs = mock.getLogs();
  assert(logs.some(l => l.msg.includes("filesystems: 1 mounted partition(s) inspected")));
  assert(logs.some(l => l.msg.includes("/data") && l.msg.includes("ufs")));
  assert(!logs.some(l => l.msg.includes("/mnt/usb0")));
  assert.equal(mock.openedFds.size, 0);
}

// Test 3: Raw bytes formatting
{
  const mock = createMockApi({ args: ["bytes", "/data"] });
  await entry(mock);

  const logs = mock.getLogs();
  // 174850048 blocks * 4096 = 716185796608 bytes
  assert(logs.some(l => l.msg.includes("716185796608")));
  assert.equal(mock.openedFds.size, 0);
}

// Test 4: Inodes view
{
  const mock = createMockApi({ args: ["inodes", "/user"] });
  await entry(mock);

  const logs = mock.getLogs();
  assert(logs.some(l => l.msg.includes("Inodes") && l.msg.includes("IUsed")));
  // 2M total, 200k used (2000000 - 1800000), 10%
  assert(logs.some(l => l.msg.includes("2M") && l.msg.includes("200k") && l.msg.includes("10%")));
  assert.equal(mock.openedFds.size, 0);
}

// Test 5: Mount flags decoding
{
  const mock = createMockApi({ args: ["flags", "/"] });
  await entry(mock);

  const logs = mock.getLogs();
  assert(logs.some(l => l.msg.includes("read-only") && l.msg.includes("rootfs")));
  assert.equal(mock.openedFds.size, 0);
}

// Test 6: Structured JSON output
{
  const mock = createMockApi({ args: ["json", "/data"] });
  await entry(mock);

  const logs = mock.getLogs();
  assert.equal(logs.length, 1);
  const data = JSON.parse(logs[0].msg);
  assert.equal(Array.isArray(data), true);
  assert.equal(data.length, 1);
  assert.equal(data[0].mounted_on, "/data");
  assert.equal(data[0].type, "ufs");
  assert.equal(data[0].total_bytes, 174850048 * 4096);
  assert.deepEqual(data[0].flags, ["local"]);
  assert.equal(mock.openedFds.size, 0);
}

// Test 7: Help argument
{
  const mock = createMockApi({ args: ["help"] });
  await entry(mock);

  const logs = mock.getLogs();
  assert(logs.some(l => l.msg.includes("Usage: df.js")));
  assert(logs.some(l => l.msg.includes("inodes")));
}

// Test 8: Deduplication of same mount point
{
  const duplicateMounts = [
    {
      path: "/",
      filesystem: "/dev/ssd0.0",
      mountedOn: "/",
      type: "ufs",
      bsize: 4096,
      iosize: 65536,
      totalBlocks: 1000,
      freeBlocks: 500,
      availBlocks: 500,
      totalInodes: 100,
      freeInodes: 50,
      flags: 0,
    },
    {
      path: "/system",
      filesystem: "/dev/ssd0.0",
      mountedOn: "/", // Same underlying mount
      type: "ufs",
      bsize: 4096,
      iosize: 65536,
      totalBlocks: 1000,
      freeBlocks: 500,
      availBlocks: 500,
      totalInodes: 100,
      freeInodes: 50,
      flags: 0,
    },
  ];

  const mock = createMockApi({ mounts: duplicateMounts });
  await entry(mock);

  const logs = mock.getLogs();
  // Should deduplicate to 1 partition
  assert(logs.some(l => l.msg.includes("filesystems: 1 mounted partition(s) inspected")));
}

// Test 9: All option shows duplicates / all probes
{
  const duplicateMounts = [
    {
      path: "/",
      filesystem: "/dev/ssd0.0",
      mountedOn: "/",
      type: "ufs",
      bsize: 4096,
      iosize: 65536,
      totalBlocks: 1000,
      freeBlocks: 500,
      availBlocks: 500,
      totalInodes: 100,
      freeInodes: 50,
      flags: 0,
    },
    {
      path: "/system",
      filesystem: "/dev/ssd0.0",
      mountedOn: "/",
      type: "ufs",
      bsize: 4096,
      iosize: 65536,
      totalBlocks: 1000,
      freeBlocks: 500,
      availBlocks: 500,
      totalInodes: 100,
      freeInodes: 50,
      flags: 0,
    },
  ];

  const mock = createMockApi({ mounts: duplicateMounts, args: ["all"] });
  await entry(mock);

  const logs = mock.getLogs();
  assert(logs.some(l => l.msg.includes("filesystems: 2 mounted partition(s) inspected")));
}

// Test 10: Missing SYS_FSTATFS handling
{
  const mock = createMockApi({ omitFstatfs: true });
  await entry(mock);

  const logs = mock.getLogs();
  assert(logs.some(l => l.type === "error" && l.msg.includes("SYS_FSTATFS")));
}

// Test 11: Inaccessible explicit path
{
  const mock = createMockApi({ args: ["/mnt/nonexistent"] });
  await entry(mock);

  const logs = mock.getLogs();
  assert(logs.some(l => l.type === "warn" && l.msg.includes("/mnt/nonexistent")));
}

console.log("All df_test.js tests passed!");
