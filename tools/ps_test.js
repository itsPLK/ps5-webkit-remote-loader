// Unit test for payloads/ps.js with mock sysctl syscalls.
// Run: node tools/ps_test.js

import assert from "node:assert/strict";
import fs from "node:fs";
import { int64 } from "../src/utils/int64.js";

const source = fs.readFileSync(new URL("../payloads/ps.js", import.meta.url), "utf8");
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

const DEFAULT_PROCS = [
  { pid: 0, ppid: 0, uid: 0, name: "kernel" },
  { pid: 1, ppid: 0, uid: 0, name: "mini-syscore.elf" },
  { pid: 52, ppid: 1, uid: 0, name: "SceSysCore.elf" },
  { pid: 56, ppid: 52, uid: 0, name: "SceShellCore" },
  { pid: 57, ppid: 52, uid: 0, name: "SceShellUI" },
  { pid: 76, ppid: 52, uid: 1, name: "SceNKNetworkProcess" },
  { pid: 77, ppid: 52, uid: 0, name: "SceNKWebProcess" },
  { pid: 80, ppid: 68, uid: 1, name: "elfldr.elf" },
];

const ENTRY_SIZE = 1096;

function createMockApi(options = {}) {
  const logs = [];
  const procs = options.procs || DEFAULT_PROCS;
  const selfPid = options.selfPid ?? 77;

  const p = {
    malloc(size, type) {
      assert.equal(type, 1);
      return pointer(Buffer.alloc(size + 1024));
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
      // SYS_GETPID = 0x014
      if (num === 0x014) {
        return ok(selfPid);
      }

      // SYS___SYSCTL = 0x0CA
      if (num === 0x0ca) {
        if (options.failSysctl) return failure();

        const [mibPtr, mibLen, oldPtr, lenPtr] = args;
        const mib0 = mibPtr.buffer.readUInt32LE(mibPtr.low);
        const mib1 = mibPtr.buffer.readUInt32LE(mibPtr.low + 4);
        const mib2 = mibPtr.buffer.readUInt32LE(mibPtr.low + 8);

        // Expect CTL_KERN (1), KERN_PROC (14), KERN_PROC_PROC (8)
        if (mib0 !== 1 || mib1 !== 14 || mib2 !== 8) {
          return failure();
        }

        const totalBytes = procs.length * ENTRY_SIZE;

        // Size probe
        if (!oldPtr || oldPtr === 0 || oldPtr.low === undefined) {
          lenPtr.buffer.writeUInt32LE(totalBytes, lenPtr.low);
          return ok(0);
        }

        // Data read
        for (let i = 0; i < procs.length; i++) {
          const item = procs[i];
          const base = oldPtr.low + i * ENTRY_SIZE;
          oldPtr.buffer.writeUInt32LE(ENTRY_SIZE, base); // structSize
          oldPtr.buffer.writeUInt32LE(item.pid, base + 72); // ki_pid
          oldPtr.buffer.writeUInt32LE(item.ppid, base + 76); // ki_ppid
          oldPtr.buffer.writeUInt32LE(item.uid, base + 176); // ki_uid

          // ki_tdname at 447
          const nameBuf = Buffer.from(item.name, "utf8");
          nameBuf.copy(oldPtr.buffer, base + 447, 0, Math.min(nameBuf.length, 31));
          oldPtr.buffer.writeUInt8(0, base + 447 + Math.min(nameBuf.length, 31));
        }

        lenPtr.buffer.writeUInt32LE(totalBytes, lenPtr.low);
        return ok(0);
      }

      return failure();
    },
  };

  return {
    p,
    chain,
    args: options.args || [],
    async log(msg, level = "info") {
      logs.push({ msg, level });
    },
    isFailure: (v) => !v || v.hi === 0xffffffff || v.low === 0xffffffff,
    describe: (v) => `0x${v.low.toString(16)}`,
    logs,
  };
}

async function run() {
  // Test 1: Default process list table
  {
    const api = createMockApi();
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /processes: 8 total/);
    assert.match(text, /PID\s+PPID\s+UID\s+NAME/);
    assert.match(text, /0\s+0\s+0\s+kernel/);
    assert.match(text, /57\s+52\s+0\s+SceShellUI/);
    assert.match(text, /77\s+52\s+0\s+SceNKWebProcess\s+\*/); // Current process marker
    assert.match(text, /80\s+68\s+1\s+elfldr\.elf/);
  }

  // Test 2: Substring filter (positional argument)
  {
    const api = createMockApi({ args: ["shell"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /processes: 8 total \(2 matched\)/);
    assert.match(text, /SceShellCore/);
    assert.match(text, /SceShellUI/);
    assert.doesNotMatch(text, /kernel/);
  }

  // Test 3: Grep option
  {
    const api = createMockApi({ args: ["grep=elf"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /processes: 8 total \(3 matched\)/);
    assert.match(text, /mini-syscore\.elf/);
    assert.match(text, /SceSysCore\.elf/);
    assert.match(text, /elfldr\.elf/);
    assert.doesNotMatch(text, /SceShellUI/);
  }

  // Test 4: PID filter
  {
    const api = createMockApi({ args: ["pid=80"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /processes: 8 total \(1 matched\)/);
    assert.match(text, /80\s+68\s+1\s+elfldr\.elf/);
    assert.doesNotMatch(text, /SceShellUI/);
  }

  // Test 5: Pure numeric argument treated as PID
  {
    const api = createMockApi({ args: ["57"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /processes: 8 total \(1 matched\)/);
    assert.match(text, /57\s+52\s+0\s+SceShellUI/);
    assert.doesNotMatch(text, /elfldr\.elf/);
  }

  // Test 6: UID filter
  {
    const api = createMockApi({ args: ["uid=1"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /processes: 8 total \(2 matched\)/);
    assert.match(text, /SceNKNetworkProcess/);
    assert.match(text, /elfldr\.elf/);
    assert.doesNotMatch(text, /SceShellUI/);
  }

  // Test 7: Sorting and reverse
  {
    const api = createMockApi({ args: ["sort=name", "limit=3"] });
    await entry(api);
    const names = api.logs
      .filter((l) => /^\s*\d+/.test(l.msg))
      .map((l) => l.msg.trim().split(/\s+/)[3]);
    assert.deepEqual(names, ["elfldr.elf", "kernel", "mini-syscore.elf"]);
  }

  // Test 8: Reverse PID sorting
  {
    const api = createMockApi({ args: ["desc", "limit=2"] });
    await entry(api);
    const pids = api.logs
      .filter((l) => /^\s*\d+/.test(l.msg))
      .map((l) => parseInt(l.msg.trim().split(/\s+/)[0], 10));
    assert.deepEqual(pids, [80, 77]);
  }

  // Test 9: JSON mode
  {
    const api = createMockApi({ args: ["json", "grep=shell"] });
    await entry(api);
    assert.equal(api.logs.length, 1);
    const parsed = JSON.parse(api.logs[0].msg);
    assert.equal(parsed.length, 2);
    assert.equal(parsed[0].name, "SceShellCore");
    assert.equal(parsed[1].name, "SceShellUI");
    assert.equal(parsed[1].pid, 57);
    assert.equal(parsed[1].self, false);
  }

  // Test 10: Help flag
  {
    const api = createMockApi({ args: ["--help"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /Usage: ps\.js/);
    assert.doesNotMatch(text, /processes: 8 total/);
  }

  // Test 11: Sysctl probe failure
  {
    const api = createMockApi({ failSysctl: true });
    await entry(api);
    const errLog = api.logs.find((l) => l.level === "error");
    assert.ok(errLog);
    assert.match(errLog.msg, /sysctl\(KERN_PROC_PROC\) probe failed/);
  }

  console.log("All ps_test.js tests passed!");
}

run();
