// Exercise the loader and Python sender over local TCP with simulated syscalls.

import net from "node:net";
import { spawn } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const { runLoader } = await import(pathToFileURL(join(ROOT, "src/loader.js")).href);

let failures = 0, checks = 0;
function check(label, ok, detail = "") {
  checks++;
  console.log(`  ${ok ? "ok  " : "FAIL"}  ${label}${detail ? "  " + detail : ""}`);
  if (!ok) failures++;
}

/*
 * A fake console whose socket is a real TCP server. p is Buffer-backed (see
 * selftest.js for why), and each read/write syscall moves real bytes between
 * memory and the accepted connection.
 */
function makeFake() {
  const p = {
    libKernelBase: { low: 0x7f200000, hi: 0, add32(d) { return { ...this, low: (this.low + d) >>> 0 }; } },
    libSceNKWebKitBase: { low: 0x7f000000, hi: 0 },
    libSceLibcInternalBase: { low: 0x7f100000, hi: 0 },
    gadgets: {}, syscalls: {},
    malloc(size) {
      const buf = Buffer.alloc(Math.max(64, (size | 0) + 64));
      const view = (off) => {
        const v = { low: off >>> 0, hi: 0, _buf: buf };
        v.add32 = (d) => view(off + d);
        return v;
      };
      return view(0);
    },
    write1(a, v) { a._buf.writeUInt8(v & 0xff, a.low); },
    write2(a, v) { a._buf.writeUInt16LE(v & 0xffff, a.low); },
    write4(a, v) { a._buf.writeUInt32LE(v >>> 0, a.low); },
    write8(a, v) {
      a._buf.writeUInt32LE(v.low >>> 0, a.low);
      a._buf.writeUInt32LE(v.hi >>> 0, a.low + 4);
    },
    read1(a) { return a._buf.readUInt8(a.low); },
    read2(a) { return a._buf.readUInt16LE(a.low); },
    read4(a) { return a._buf.readUInt32LE(a.low); },
    read8(a) { return { low: a._buf.readUInt32LE(a.low), hi: a._buf.readUInt32LE(a.low + 4) }; },
    leakval() { return { low: 0, hi: 0 }; },
    stringify(str) {
      const buf = Buffer.alloc(str.length + 1);
      buf.write(str, "utf8");
      const view = (off) => ({
        low: off >>> 0,
        hi: 0,
        _buf: buf,
        add32: (d) => view(off + d),
      });
      return view(0);
    },
  };

  // maxServes 2 so the second client (the --status command) is served too.
  // acceptSlot is the result address of an in-flight accept. A real worker
  // parks in the kernel and fills it whenever a connection lands; here the
  // server's connection handler fills it, which is the same observable event.
  const io = {
    conn: null, pending: Buffer.alloc(0), served: 0, maxServes: 2,
    acceptSlot: null, onConnect: null,
  };
  let detached = null;

  const chain = {
    pre_chain() {}, clear() {}, push() {}, push_write8() {}, fcall() {}, write_result() {},
    add_syscall_ret(retstore, nr, ...args) { detached = { retstore, nr, args }; },
    async syscall(nr, ...args) {
      switch (nr) {
        case 0x061: return { low: 10, hi: 0 };            // socket
        case 0x01e: return { low: 11, hi: 0 };            // accept
        case 0x014: return { low: 4242, hi: 0 };          // getpid
        case 0x003: {                                     // read
          if (io.pending.length === 0) return { low: 0xffffffff, hi: 0 };
          const want = (args[2] >>> 0) || io.pending.length;
          // read() is not a drain: it must return the FULL requested count when
          // that much is buffered, because the loader loops on short reads to
          // fill its payload buffer. Clamping to what arrived is right for a
          // socket but wrong here, and it made the loader read the 8-byte
          // header and then stop.
          const n = Math.min(want, io.pending.length);
          const chunk = io.pending.subarray(0, n);
          for (let i = 0; i < n; i++) {
            const at = args[1].add32(i);
            at._buf.writeUInt8(chunk[i], at.low);
          }
          io.pending = io.pending.subarray(n);
          return { low: n, hi: 0 };
        }
        case 0x004: {                                     // write
          const len = args[2] >>> 0;
          const out = Buffer.alloc(len);
          for (let i = 0; i < len; i++) {
            const at = args[1].add32(i);
            out[i] = at._buf.readUInt8(at.low);
          }
          io.conn?.write(out);
          return { low: len, hi: 0 };
        }
        case 0x005: return { low: 0xffffffff, hi: 0xffffffff }; // open
        case 0x006: {                                     // close
          // Defer the FIN by a tick. Calling end() in the same tick as the
          // last write() races the flush, and the log lines were being dropped
          // before send.py could read them -- which is why this test only
          // passed when a debug print happened to slow things down.
          const c = io.conn;
          io.conn = null;
          if (c) setImmediate(() => c.end());
          return { low: 0, hi: 0 };
        }
        default: return { low: 0, hi: 0 };
      }
    },
  };

  // accept() must behave like the real thing: park until a client connects,
  // then write the result slot. The real worker does this inside the kernel;
  // here io.onConnect does it when the server accepts, so net.js's poll loop
  // sees the same sequence of events.
  p.launch_chain_detached = () => {
    if (!detached) return;
    const { retstore, nr } = detached;
    detached = null;
    if (nr === 0x01e) {
      io.acceptSlot = retstore;   // filled by the connection handler
      if (io.pendingConn) {       // a client that raced us
        const c = io.pendingConn;
        io.pendingConn = null;
        io.acceptSlot = null;
        io.served++;
        p.write8(retstore, { low: 11, hi: 0 });
        io.conn = c;
      }
      return;
    }
    p.write8(retstore, { low: 0, hi: 0 });
  };
  p.launch_chain = async () => {};

  return { p, chain, io };
}

const PORT = 19027;

function runSender(argv) {
  return new Promise((resolve) => {
    const child = spawn("python3", [join(HERE, "send.py"), ...argv],
      { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => { out += d; });
    child.stderr.on("data", (d) => { err += d; });
    child.on("close", (code) => resolve({ code, out, err }));
  });
}

console.log("end-to-end: real loader + real send.py over real TCP\n");

// The fake console: accept from send.py, wire it to the loader's syscalls.
const { p, chain, io } = makeFake();

const server = net.createServer((conn) => {
  conn.on("data", (d) => { io.pending = Buffer.concat([io.pending, d]); });

  // Completing a pending accept is this fake's stand-in for the worker
  // returning from accept() in the kernel.
  if (io.acceptSlot) {
    const slot = io.acceptSlot;
    io.acceptSlot = null;
    io.served++;
    p.write8(slot, { low: 11, hi: 0 });
    io.conn = conn;
  } else {
    io.pendingConn = conn;
  }
});

await new Promise((r) => server.listen(PORT, "127.0.0.1", r));

// Drive the loader in the background; it serves up to maxServes connections.
const loaderDone = runLoader(p, chain, () => {}).catch(() => {});

// Give the loader a moment to reach its accept loop before the client dials.
await new Promise((r) => setTimeout(r, 300));

// A payload on disk, sent by the real sender. Bounded so a protocol mismatch
// fails the test instead of hanging it.
const payloadPath = join(ROOT, "payloads", "hello_world.js");
const r1 = await Promise.race([
  runSender(["127.0.0.1", String(PORT), payloadPath]),
  new Promise((r) => setTimeout(() => r({ code: -1, out: "", err: "timed out" }), 20000)),
]);

check("send.py exits cleanly", r1.code === 0, `rc=${r1.code} ${r1.err.trim()}`);
check("send.py reports the byte count", /sent \d+ bytes/.test(r1.out),
  r1.out.split("\n")[0] || "");
check("payload logs stream back", r1.out.includes("hello world from payload"),
  r1.out.includes("hello world from payload") ? "" : r1.out.slice(0, 300));
check("the loader reports completion", r1.out.includes("payload done"));
check("krw is advertised as absent", /krw .*not established|null/.test(r1.out));

// argv over the real wire, using the real sender
const argPayload = join(ROOT, "payloads", "readfile.js");
const rArg = await Promise.race([
  runSender(["127.0.0.1", String(PORT), argPayload, "--arg", "/etc/hosts", "--arg", "two words"]),
  new Promise((r) => setTimeout(() => r({ code: -1, out: "", err: "timed out" }), 20000)),
]);
check("argv round-trips through the real sender", rArg.out.includes("open(/etc/hosts)"),
  rArg.err || rArg.out.trim().split("\n").pop() || "");
check("an argument with a space survives", rArg.out.includes("open(two words)"));

// A status command, same wire protocol, no payload.
const r2 = await Promise.race([
  runSender(["127.0.0.1", String(PORT), "--status"]),
  new Promise((r) => setTimeout(() => r({ code: -1, out: "", err: "timed out" }), 20000)),
]);
check("the status command round-trips", /up: fd|command: status/.test(r2.out),
  r2.err || r2.out.trim().split("\n").pop() || "");

server.close();
await Promise.race([loaderDone, new Promise((r) => setTimeout(r, 500))]);

console.log(`\n${checks - failures}/${checks} checks passed`);
process.exit(failures ? 1 : 0);
