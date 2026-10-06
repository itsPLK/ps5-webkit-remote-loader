// Read or follow /dev/klog.

const SYS_OPEN = 0x005;
const SYS_CLOSE = 0x006;
const SYS_READ = 0x003;
const SYS_POLL = 0x0d1;
const SYS_GETUID = 0x018;

const O_RDONLY = 0x0000;
const O_NONBLOCK = 0x0004;
const POLLIN = 0x0001;

const CHUNK = 0x1000; // 4 KiB read buffer

return async function (api) {
  let follow = false;
  let followSec = 30;
  let filter = null;
  let keepRaw = false;

  for (const arg of api.args || []) {
    if (arg === "follow" || arg === "-f") {
      follow = true;
    } else if (arg === "raw") {
      keepRaw = true;
    } else if (arg.startsWith("grep=") || arg.startsWith("filter=")) {
      filter = arg.slice(arg.indexOf("=") + 1).toLowerCase();
    } else if (arg.startsWith("timeout=") || arg.startsWith("sec=")) {
      followSec = Math.max(1, Number(arg.slice(arg.indexOf("=") + 1)) || 30);
      follow = true;
    } else if (/^\d+$/.test(arg)) {
      followSec = Math.max(1, Number(arg));
      follow = true;
    }
  }

  // Pre-flight check: /dev/klog is restricted to root in FreeBSD.
  const uid = (await api.chain.syscall(SYS_GETUID)).low >>> 0;
  if (uid !== 0 && !api.krw) {
    await api.log("/dev/klog requires root privileges (run payloads/relapse.js first)", "warn");
  }

  const pathPtr = api.p.stringify("/dev/klog");
  const fd = await api.chain.syscall(SYS_OPEN, pathPtr, O_RDONLY | O_NONBLOCK);
  if (api.isFailure(fd)) {
    await api.log(`open(/dev/klog) failed: ${api.describe(fd)} (requires root/unsandboxed process)`, "error");
    return;
  }

  // Scratch memory: read buffer (4096 bytes) + struct pollfd (8 bytes)
  const arena = api.p.malloc(CHUNK + 64, 1);
  const readBuf = arena;
  const pollfd = arena.add32(CHUNK);

  api.p.write4(pollfd, fd.low);
  api.p.write2(pollfd.add32(4), POLLIN);
  api.p.write2(pollfd.add32(6), 0);

  let leftover = "";
  let totalBytes = 0;
  let lineCount = 0;

  async function flushLines(isLast = false) {
    const lines = leftover.split("\n");
    leftover = isLast ? "" : (lines.pop() || "");
    for (const raw of lines) {
      const trimmed = raw.replace(/\r$/, "");
      if (!trimmed) continue;
      lineCount++;
      const line = keepRaw ? trimmed : trimmed.replace(/^<\d+>/, "");
      if (!filter || line.toLowerCase().includes(filter)) {
        await api.log(line);
      }
    }
    if (isLast && leftover.replace(/\r$/, "")) {
      lineCount++;
      const line = keepRaw ? leftover : leftover.replace(/^<\d+>/, "");
      if (!filter || line.toLowerCase().includes(filter)) {
        await api.log(line);
      }
      leftover = "";
    }
  }

  await api.log(`=== Kernel Log (${follow ? `following for ${followSec}s` : "dmesg snapshot"}) ===`, "info");

  const deadline = follow ? Date.now() + followSec * 1000 : Infinity;
  const pollTimeout = follow ? 500 : 100; // ms

  try {
    for (;;) {
      if (follow && Date.now() >= deadline) break;

      api.p.write2(pollfd.add32(6), 0); // clear revents
      const pRet = await api.chain.syscall(SYS_POLL, pollfd, 1, pollTimeout);

      if (api.isFailure(pRet)) break;

      if (pRet.low === 0) {
        // In snapshot mode, a timeout means the ring buffer has been drained.
        if (!follow) break;
        continue;
      }

      const revents = api.p.read2(pollfd.add32(6));
      if (!(revents & POLLIN)) break;

      const n = await api.chain.syscall(SYS_READ, fd, readBuf, CHUNK);
      if (api.isFailure(n)) break;

      const got = n.low >>> 0;
      if (got === 0) break;

      totalBytes += got;
      let text = "";
      for (let i = 0; i < got; i++) {
        text += String.fromCharCode(api.p.read1(readBuf.add32(i)));
      }
      leftover += text;
      await flushLines(false);
    }

    await flushLines(true);
    await api.log(`=== End of Kernel Log (${lineCount} lines, ${totalBytes} bytes) ===`, "info");
  } finally {
    await api.chain.syscall(SYS_CLOSE, fd);
  }
};
