import { openListener, acceptOnce } from "../src/net.js";

class Ptr {
  constructor(offset) { this.low = offset; this.hi = 0; }
  add32(value) { return new Ptr(this.low + value); }
}
const ok = (low = 0) => ({ low: low >>> 0, hi: 0 });
const fail = () => ({ low: 0xffffffff, hi: 0xffffffff });

async function exercise() {
  const bytes = new Uint8Array(0x1000);
  let next = 0x100;
  const calls = [];
  const p = {
    malloc(size) { const out = new Ptr(next); next += size + 16; return out; },
    write1(ptr, value) { bytes[ptr.low] = value; },
    write2(ptr, value) { bytes[ptr.low] = value & 255; bytes[ptr.low + 1] = value >>> 8; },
    write4(ptr, value) { new DataView(bytes.buffer).setUint32(ptr.low, value, true); },
    read2(ptr) { return bytes[ptr.low] | (bytes[ptr.low + 1] << 8); },
  };
  const chain = {
    async syscall(number, ...args) {
      calls.push({ number, args });
      if (number === 0x061) return ok(10);
      if (number === 0x0d1) return ok(1);
      if (number === 0x01e) return ok(11);
      return ok();
    },
  };
  const listener = await openListener(p, chain, () => {}, 9027);
  const accepted = await acceptOnce(p, chain, () => {}, listener, 1000);
  if (accepted.low !== 11) throw new Error("accept result was not returned");
  return calls;
}

const calls = await exercise();
const numbers = calls.map(({ number }) => number);
const socket = calls.find(({ number }) => number === 0x061);
if (!socket || socket.args[1] !== 1)
  throw new Error("listener was not created as a plain SOCK_STREAM socket");
if (numbers.includes(0x036) || numbers.includes(0x05c))
  throw new Error("listener attempted a denied descriptor mutation");
if (numbers.indexOf(0x0d1) < 0 || numbers.indexOf(0x01e) < numbers.indexOf(0x0d1))
  throw new Error("accept was not gated by poll readiness");

console.log("Wobkot poll-gated listener setup passed");
