// Unit test for payloads/netstat.js with mock syscalls.
// Run: node tools/netstat_test.js

import assert from "node:assert/strict";
import fs from "node:fs";
import { int64 } from "../src/utils/int64.js";

const source = fs.readFileSync(new URL("../payloads/netstat.js", import.meta.url), "utf8");
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

const IF_RECORD_SIZE = 0x3c0;

function createMockApi(options = {}) {
  const logs = [];
  const openPorts = new Set(options.openPorts ?? [9021, 9027, 9295]);
  let nextSocket = 10;

  const p = {
    malloc(size, type) {
      assert.equal(type, 1);
      return pointer(Buffer.alloc(size + 1024));
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
      // SYS_NETGETIFLIST = 0x07d
      if (num === 0x07d) {
        if (options.failNetIf) return failure();
        const [listPtr, maxCount] = args;
        if (!listPtr || listPtr === 0 || listPtr.low === undefined) {
          // Probe count
          return ok(2);
        }

        // eth0 at record 0
        const b0 = listPtr.low;
        listPtr.buffer.write("eth0\0", b0, "utf8");
        listPtr.buffer.writeUInt32LE(1, b0 + 0x20); // UP
        // MAC: 78:c8:81:a8:da:c5
        const ethMac = [0x78, 0xc8, 0x81, 0xa8, 0xda, 0xc5];
        for (let i = 0; i < 6; i++) listPtr.buffer.writeUInt8(ethMac[i], b0 + 0x50 + i);
        listPtr.buffer.writeUInt32LE(1500, b0 + 0x58); // MTU

        // wlan0 at record 1
        const b1 = listPtr.low + IF_RECORD_SIZE;
        listPtr.buffer.write("wlan0\0", b1, "utf8");
        listPtr.buffer.writeUInt32LE(1, b1 + 0x20); // UP
        // IP: 192.168.1.133
        const wlanIp = [192, 168, 1, 133];
        for (let i = 0; i < 4; i++) listPtr.buffer.writeUInt8(wlanIp[i], b1 + 40 + i);
        // Netmask: 255.255.255.0
        const wlanMask = [255, 255, 255, 0];
        for (let i = 0; i < 4; i++) listPtr.buffer.writeUInt8(wlanMask[i], b1 + 0x34 + i);
        // MAC: 1c:98:c1:98:04:aa
        const wlanMac = [0x1c, 0x98, 0xc1, 0x98, 0x04, 0xaa];
        for (let i = 0; i < 6; i++) listPtr.buffer.writeUInt8(wlanMac[i], b1 + 0x50 + i);
        listPtr.buffer.writeUInt32LE(1500, b1 + 0x58); // MTU

        return ok(2);
      }

      // SYS_SOCKET = 0x061
      if (num === 0x061) {
        if (options.failSocket) return failure();
        return ok(nextSocket++);
      }

      // SYS_CONNECT = 0x062
      if (num === 0x062) {
        const [sock, sockaddrPtr] = args;
        const portHi = sockaddrPtr.buffer.readUInt8(sockaddrPtr.low + 2);
        const portLo = sockaddrPtr.buffer.readUInt8(sockaddrPtr.low + 3);
        const port = (portHi << 8) | portLo;

        if (openPorts.has(port)) {
          return ok(0);
        }
        return failure();
      }

      // SYS_CLOSE = 0x006
      if (num === 0x006) {
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
    logs,
  };
}

async function run() {
  // Test 1: Default execution (interfaces + listening ports)
  {
    const api = createMockApi();
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /=== Network Interfaces ===/);
    assert.match(text, /eth0\s+UP\s+-\s+-\s+78:c8:81:a8:da:c5\s+1500/);
    assert.match(text, /wlan0\s+UP\s+192\.168\.1\.133\s+255\.255\.255\.0\s+1c:98:c1:98:04:aa\s+1500/);
    assert.match(text, /=== Active Listening Ports \(3 open, 23 scanned\) ===/);
    assert.match(text, /9021\s+TCP\s+LISTEN\s+elfldr/);
    assert.match(text, /9027\s+TCP\s+LISTEN\s+ps5-webkit-remote-loader/);
    assert.match(text, /9295\s+TCP\s+LISTEN\s+PS Remote Play/);
  }

  // Test 2: Interfaces only (interfaces)
  {
    const api = createMockApi({ args: ["interfaces"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /=== Network Interfaces ===/);
    assert.match(text, /wlan0/);
    assert.doesNotMatch(text, /Active Listening Ports/);
  }

  // Test 3: Listen only (-l / listen)
  {
    const api = createMockApi({ args: ["listen"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.doesNotMatch(text, /Network Interfaces/);
    assert.match(text, /Active Listening Ports/);
    assert.match(text, /9021\s+TCP\s+LISTEN/);
  }

  // Test 4: Single port check
  {
    const api = createMockApi({ args: ["9021"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.doesNotMatch(text, /Network Interfaces/);
    assert.match(text, /1 open, 1 scanned/);
    assert.match(text, /9021\s+TCP\s+LISTEN/);
    assert.doesNotMatch(text, /9027/);
  }

  // Test 5: Range scan
  {
    const api = createMockApi({ args: ["range=9020-9030"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /2 open, 11 scanned/);
    assert.match(text, /9021/);
    assert.match(text, /9027/);
    assert.doesNotMatch(text, /9295/);
  }

  // Test 6: Specific ports list
  {
    const api = createMockApi({ args: ["ports=80,9021,9999"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /1 open, 3 scanned/);
    assert.match(text, /9021/);
  }

  // Test 7: JSON output
  {
    const api = createMockApi({ args: ["json"] });
    await entry(api);
    assert.equal(api.logs.length, 1);
    const data = JSON.parse(api.logs[0].msg);
    assert.equal(data.interfaces.length, 2);
    assert.equal(data.interfaces[1].name, "wlan0");
    assert.equal(data.interfaces[1].ip, "192.168.1.133");
    assert.equal(data.interfaces[1].mac, "1c:98:c1:98:04:aa");
    assert.equal(data.open_ports.length, 3);
    assert.equal(data.open_ports[0].port, 9021);
    assert.equal(data.open_ports[1].port, 9027);
  }

  // Test 8: Help output
  {
    const api = createMockApi({ args: ["help"] });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /Usage: netstat\.js/);
    assert.doesNotMatch(text, /Network Interfaces/);
  }

  // Test 9: Network interface failure handling
  {
    const api = createMockApi({ failNetIf: true });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /=== Network Interfaces ===/);
    // Open ports still work even if interfaces call fails
    assert.match(text, /Active Listening Ports/);
  }

  // Test 10: Socket failure handling
  {
    const api = createMockApi({ failSocket: true });
    await entry(api);
    const text = api.logs.map((l) => l.msg).join("\n");
    assert.match(text, /=== Network Interfaces ===/);
    assert.match(text, /0 open, 23 scanned/);
  }

  console.log("All netstat_test.js tests passed!");
}

run();
