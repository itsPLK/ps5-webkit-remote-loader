// Anonymous IPv4 FTP server; uses binary transfers for every TYPE setting.

return async function (api) {
  const SYS = {
    READ: 3, WRITE: 4, OPEN: 5, CLOSE: 6, UNLINK: 10, CHMOD: 15,
    GETPID: 20, GETUID: 24, RECVFROM: 29, ACCEPT: 30, GETSOCKNAME: 32,
    MUNMAP: 73, SOCKET: 97,
    CONNECT: 98, BIND: 104, SETSOCKOPT: 105, LISTEN: 106, GETSOCKOPT: 118,
    RENAME: 128, SENDTO: 133, MKDIR: 136, RMDIR: 137, STAT: 188,
    FSTAT: 189, GETDIRENTRIES: 196, POLL: 209, GETDENTS: 272, MMAP: 477, LSEEK: 478,
    JITSHM_CREATE: 533, JITSHM_ALIAS: 534, IS_IN_SANDBOX: 585, DLSYM: 591,
  };
  const CHUNK = 4096;
  // PS5 internal partitions (/data, /user) use 64 KiB filesystem blocks;
  // getdents(272) and getdirentries(196) reject smaller buffers with EINVAL (22).
  const DIR_CHUNK = 65536;
  const MAX_LINE = 4096;
  const NONBLOCK = 4;
  const SOL_SOCKET = 0xffff;
  // PS5 socket nonblocking option; fcntl(F_SETFL) is refused in WebKit.
  const SO_NBIO = 0x1200;
  const POLLIN = 1, POLLOUT = 4, POLLERR = 8, POLLHUP = 16, POLLNVAL = 32;
  const encoder = new TextEncoder(), decoder = new TextDecoder(), controlDecoder = new TextDecoder();
  const p = api.p;
  const sys = (nr, ...args) => api.chain.syscall(nr, ...args);
  const failed = api.isFailure;
  const pause = () => new Promise((resolve) => setTimeout(resolve, 10));
  const options = { port: 1337, path: "/", ip: "", timeout: 300, persist: false };
  for (const arg of api.args || []) {
    if (arg === "persist") { options.persist = true; continue; }
    const eq = arg.indexOf("=");
    const key = arg.slice(0, eq), value = arg.slice(eq + 1);
    if (eq < 0 || !["port", "path", "ip", "timeout"].includes(key))
      throw new Error(`unknown FTP option: ${arg}`);
    options[key] = key === "port" || key === "timeout" ? Number(value) : value;
  }
  if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535)
    throw new Error("FTP port must be from 1 to 65535");
  if (!Number.isInteger(options.timeout) || options.timeout < 1 || options.timeout > 3600)
    throw new Error("FTP timeout must be from 1 to 3600 seconds");
  const timeoutMs = options.timeout * 1000;
  const ipv4 = (s) => {
    const parts = s.split(".");
    if (parts.length !== 4 || parts.some((v) => !/^\d{1,3}$/.test(v) || Number(v) > 255))
      throw new Error("invalid IPv4 address");
    return parts.map(Number);
  };
  const advertisedIP = options.ip ? ipv4(options.ip) : null;
  // These are shared scratch regions, reused for every command and transfer.
  // malloc(..., 1) uses the loader's small Uint8Array allocation path.
  // PS5 internal partitions (/data, /user) require a 64 KiB directory buffer (0x10000).
  const arena = p.malloc(0x14000, 1);
  const io = arena, control = arena.add32(0x1000);
  const pathA = arena.add32(0x2000), pathB = arena.add32(0x3000), dirents = arena.add32(0x4000);
  const meta = p.malloc(256, 1);
  const st = meta, addr = meta.add32(128), addrlen = meta.add32(144);
  const pollfd = meta.add32(152), opt = meta.add32(160), optlen = meta.add32(164);
  const dirbase = meta.add32(176); // getdirentries writes an eight-byte base offset.
  const dirResult = meta.add32(184), errnoResult = meta.add32(192), symbolResult = meta.add32(200);
  let workerErrno = null, errnoResolved = false;
  let errnoUnavailable = "not resolved";
  let rawDirectoryCall = null, rawMapping = null, rawWritable = null;
  const RAW_PAGE_SIZE = 0x4000;
  const openFDs = new Set();
  let listener = null, ctrl = null, passive = null, data = null;
  let active = null, cwd = "/", restart = null, renameFrom = null, stopped = false;
  let localIP = null, peerIP = null;

  class FTPError extends Error {
    constructor(code, message) { super(message); this.code = code; }
  }
  function putBytes(ptr, bytes) {
    for (let i = 0; i < bytes.length; i++) p.write1(ptr.add32(i), bytes[i]);
  }
  function getBytes(ptr, n) {
    const bytes = new Uint8Array(n);
    for (let i = 0; i < n; i++) bytes[i] = p.read1(ptr.add32(i));
    return bytes;
  }
  function pathPtr(path, ptr = pathA) {
    const bytes = encoder.encode(path);
    if (bytes.length >= MAX_LINE || /[\0\r\n]/.test(path))
      throw new FTPError(501, "Invalid or oversized path");
    putBytes(ptr, bytes);
    p.write1(ptr.add32(bytes.length), 0);
    return ptr;
  }
  function resolvePath(path, base = cwd) {
    if (!path || /[\0\r\n]/.test(path)) throw new FTPError(501, "Path required");
    const parts = [];
    for (const part of (path.startsWith("/") ? path : `${base}/${path}`).split("/")) {
      if (part === "..") parts.pop();
      else if (part && part !== ".") parts.push(part);
    }
    const result = "/" + parts.join("/");
    pathPtr(result); // Validate length before any native call.
    return result;
  }
  function checked(rv, name, code = 550) {
    if (failed(rv)) throw new FTPError(code, `${name} failed (missing or denied)`);
    return rv.low >>> 0;
  }
  async function resolveWorkerErrno() {
    if (errnoResolved) return;
    errnoResolved = true;
    const chain = api.chain, gadgets = api.gadgets || {};
    const missing = ["clear", "push", "add_syscall_ret", "write_result", "run", "call"]
      .filter((key) => typeof chain[key] !== "function");
    missing.push(...["pop rax", "pop rdi", "mov rax, [rax]", "mov [rdi], eax"].filter((key) => !gadgets[key]));
    if (missing.length) { errnoUnavailable = "missing " + missing.join("/"); return; }
    // Try the libkernel handles used by PS5 loaders. This is the direct
    // dlsym syscall, which can still be refused with uid=0 and sandbox=0;
    // the SDK's kernel_dynlib_dlsym uses a different resolver.
    let resolved = false;
    const failures = [];
    for (const handle of [0x2001, 1]) {
      p.write4(symbolResult, 0); p.write4(symbolResult.add32(4), 0);
      const rv = await sys(SYS.DLSYM, handle, pathPtr("__error"), symbolResult);
      if (!failed(rv) && rv.low === 0) { resolved = true; break; }
      failures.push(`handle 0x${handle.toString(16)}=` + (api.describe ? api.describe(rv) : String(rv.low >>> 0)));
    }
    if (!resolved) {
      errnoUnavailable = "dlsym(__error): " + failures.join("/");
      await api.log("FTP: could not resolve libkernel __error; trying direct kernel-error capture", "warn");
      await prepareRawDirectoryReader();
      return;
    }
    const symbol = p.read8(symbolResult);
    // PS5 userland pointers commonly exceed 4 GiB (e.g. 0x8xxxxxxxx).
    // Accept canonical lower-half addresses, including nonzero upper dwords.
    const validPointer = (ptr) => ptr && (ptr.hi >>> 0) < 0x8000 &&
      ((ptr.hi >>> 0) !== 0 || (ptr.low >>> 0) >= 0x10000);
    const addressText = (ptr) => "0x" + (ptr.hi >>> 0).toString(16) + (ptr.low >>> 0).toString(16).padStart(8, "0");
    if (!validPointer(symbol)) { errnoUnavailable = "invalid __error address " + addressText(symbol); return; }
    // __error is thread-local: call it on the same ROP worker that lists files.
    const address = await chain.call(symbol);
    if (validPointer(address) && !(address.low & 3)) workerErrno = address;
    else errnoUnavailable = "invalid errno pointer " + addressText(address);
  }
  async function prepareRawDirectoryReader() {
    // Preserve the kernel's carry/error result before libkernel turns it into
    // -1. This leaf function changes no credentials or syscall restrictions.
    // Its assembly source is tools/ftp_raw_syscall.S. Only four syscall args
    // are needed here: nr, fd, buffer, length, basep (getdirentries only).
    const code = [0x48, 0x89, 0xf8, 0x48, 0x89, 0xf7, 0x48, 0x89, 0xd6,
      0x48, 0x89, 0xca, 0x4d, 0x89, 0xc2, 0x0f, 0x05, 0x73, 0x03,
      0x48, 0xf7, 0xd8, 0xc3];
    const plausible = (ptr) => (ptr.hi >>> 0) < 0x8000 &&
      ((ptr.hi >>> 0) !== 0 || (ptr.low >>> 0) >= 0x10000);
    const unavailable = (reason) => { errnoUnavailable += "; raw reader: " + reason; };
    // Use the PS5 JIT object/alias path already used by src/kexp.js. An
    // anonymous RW mapping cannot simply be mprotected to executable on PS5.
    // The RX and RW views are separate, with no RWX view or kernel patches.
    const execResult = await sys(SYS.JITSHM_CREATE, 0, RAW_PAGE_SIZE, 7);
    if (failed(execResult) || execResult.low >= 0x100000) { unavailable("jitshm_create failed"); return; }
    const execFD = execResult.low >>> 0;
    openFDs.add(execFD);
    const mapped = await sys(SYS.MMAP, 0, RAW_PAGE_SIZE, 5, 1, execFD, 0);
    if (!plausible(mapped)) { unavailable("JIT RX mmap failed"); return; }
    rawMapping = mapped;
    const aliasResult = await sys(SYS.JITSHM_ALIAS, execFD, 3);
    if (failed(aliasResult) || aliasResult.low >= 0x100000) { unavailable("jitshm_alias failed"); return; }
    const writeFD = aliasResult.low >>> 0;
    openFDs.add(writeFD);
    const writable = await sys(SYS.MMAP, 0, RAW_PAGE_SIZE, 3, 1, writeFD, 0);
    if (!plausible(writable)) { unavailable("JIT RW mmap failed"); return; }
    rawWritable = writable;
    putBytes(writable, code);
    if (getBytes(writable, code.length).some((byte, i) => byte !== code[i])) {
      unavailable("code verification failed"); return;
    }
    const unmapped = await sys(SYS.MUNMAP, writable, RAW_PAGE_SIZE);
    if (failed(unmapped) || unmapped.low !== 0) { unavailable("JIT RW munmap failed"); return; }
    rawWritable = null;
    await close(writeFD);
    await close(execFD);
    const pid = await sys(SYS.GETPID);
    const probe = await api.chain.call(mapped, SYS.GETPID, 0, 0, 0, 0);
    if (failed(pid) || probe.low !== pid.low || probe.hi !== pid.hi) {
      const detail = probe.hi === 0xffffffff ? "errno=" + ((0 - probe.low) >>> 0) : "unexpected return";
      unavailable("getpid probe failed (" + detail + ")"); return;
    }
    rawDirectoryCall = mapped;
    await api.log("FTP: directory reader captures kernel errors directly; native getpid probe passed", "info");
  }
  async function directoryRead(nr, fd) {
    if (rawDirectoryCall) {
      const value = await api.chain.call(rawDirectoryCall, nr, fd, dirents, DIR_CHUNK,
        nr === SYS.GETDIRENTRIES ? dirbase : 0);
      if (value.hi === 0xffffffff)
        return { rv: new api.int64(0xffffffff, 0xffffffff), errno: (0 - value.low) >>> 0 };
      if (value.hi !== 0) throw new FTPError(451, "Invalid native directory return value");
      return { rv: value, errno: 0 };
    }
    const args = nr === SYS.GETDIRENTRIES ? [fd, dirents, DIR_CHUNK, dirbase] : [fd, dirents, DIR_CHUNK];
    if (!workerErrno) return { rv: await sys(nr, ...args), errno: null };
    const chain = api.chain, gadgets = api.gadgets;
    chain.clear();
    // Clear and copy errno inside one gated batch. Log/socket calls and the
    // worker's return to JavaScript must not overwrite it before we capture it.
    chain.push(gadgets["pop rdi"]); chain.push(workerErrno);
    chain.push(gadgets["pop rax"]); chain.push(0);
    chain.push(gadgets["mov [rdi], eax"]);
    chain.add_syscall_ret(dirResult, nr, ...args);
    chain.push(gadgets["pop rax"]); chain.push(workerErrno);
    chain.push(gadgets["mov rax, [rax]"]);
    chain.write_result(errnoResult);
    await chain.run();
    return { rv: p.read8(dirResult), errno: p.read4(errnoResult) >>> 0 };
  }
  function directoryError(result) {
    const native = api.describe ? api.describe(result.rv) : `0x${(result.rv.low >>> 0).toString(16)}`;
    if (result.errno === null) return native + "; errno unavailable (" + errnoUnavailable + ")";
    const errors = { 1: "EPERM", 5: "EIO", 9: "EBADF", 13: "EACCES", 14: "EFAULT",
      20: "ENOTDIR", 22: "EINVAL", 35: "EAGAIN", 45: "EOPNOTSUPP", 78: "ENOSYS",
      93: "ENOTCAPABLE", 94: "ECAPMODE" };
    return `${native}; errno=${result.errno}${errors[result.errno] ? " (" + errors[result.errno] + ")" : ""}`;
  }
  function number64(ptr) {
    const value = p.read8(ptr);
    const n = (value.low >>> 0) + (value.hi >>> 0) * 0x100000000;
    if (!Number.isSafeInteger(n)) throw new FTPError(550, "File metadata exceeds numeric range");
    return n;
  }
  function statResult() {
    // PS5's FreeBSD 11 stat ABI: mode +8, mtime +40, size +72 (120 bytes).
    return { mode: p.read2(st.add32(8)), size: number64(st.add32(72)),
      mtime: number64(st.add32(40)) };
  }
  async function stat(path) {
    checked(await sys(SYS.STAT, pathPtr(path), st), "stat");
    return statResult();
  }
  const isDir = (s) => (s.mode & 0xf000) === 0x4000;
  const isFile = (s) => (s.mode & 0xf000) === 0x8000;
  async function close(fd) {
    if (fd === null || !openFDs.delete(fd)) return;
    await sys(SYS.CLOSE, fd);
  }
  async function open(path, flags, nonblocking = true) {
    const fd = checked(await sys(SYS.OPEN, pathPtr(path), flags | (nonblocking ? NONBLOCK : 0), 0o644), "open");
    openFDs.add(fd);
    return fd;
  }
  async function nonblocking(fd) {
    p.write4(opt, 1);
    const rv = await sys(SYS.SETSOCKOPT, fd, SOL_SOCKET, SO_NBIO, opt, 4);
    if (failed(rv)) {
      const result = api.describe ? api.describe(rv) : `0x${(rv.low >>> 0).toString(16)}`;
      throw new FTPError(425, `setsockopt(SO_NBIO=0x1200) failed: ${result}`);
    }
  }
  async function socket() {
    const fd = checked(await sys(SYS.SOCKET, 2, 1, 0), "socket", 425);
    openFDs.add(fd);
    try { await nonblocking(fd); return fd; }
    catch (e) { await close(fd); throw e; }
  }
  function sockaddr(ip, port) {
    for (let i = 0; i < 16; i++) p.write1(addr.add32(i), 0);
    p.write1(addr.add32(1), 2);
    p.write1(addr.add32(2), port >>> 8);
    p.write1(addr.add32(3), port & 255);
    ip.forEach((octet, i) => p.write1(addr.add32(4 + i), octet));
    return addr;
  }
  const addressIP = () => Array.from({ length: 4 }, (_, i) => p.read1(addr.add32(4 + i)));
  async function name(fd) {
    p.write4(addrlen, 16);
    checked(await sys(SYS.GETSOCKNAME, fd, addr, addrlen), "getsockname", 425);
    return { ip: addressIP(), port: p.read1(addr.add32(2)) * 256 + p.read1(addr.add32(3)) };
  }
  async function listen(port) {
    const fd = await socket();
    try {
      p.write4(opt, 1);
      checked(await sys(SYS.SETSOCKOPT, fd, SOL_SOCKET, 4, opt, 4), "setsockopt", 425);
      checked(await sys(SYS.BIND, fd, sockaddr([0, 0, 0, 0], port), 16), "bind", 425);
      checked(await sys(SYS.LISTEN, fd, 4), "listen", 425);
      return fd;
    } catch (e) { await close(fd); throw e; }
  }
  async function wait(fd, events, deadline) {
    for (;;) {
      if (Date.now() >= deadline) throw new FTPError(426, "Connection timed out");
      p.write4(pollfd, fd);
      p.write2(pollfd.add32(4), events);
      p.write2(pollfd.add32(6), 0);
      const n = checked(await sys(SYS.POLL, pollfd, 1, 0), "poll", 426);
      if (n) {
        const revents = p.read2(pollfd.add32(6));
        if (revents & (POLLERR | POLLNVAL)) throw new FTPError(426, "Socket error");
        if ((revents & POLLHUP) && !(events & POLLIN))
          throw new FTPError(426, "Data connection closed");
        if (revents & (events | POLLHUP)) return;
      }
      await pause();
    }
  }
  async function accept(fd, deadline) {
    for (;;) {
      await wait(fd, POLLIN, deadline);
      p.write4(addrlen, 16);
      const rv = await sys(SYS.ACCEPT, fd, addr, addrlen);
      if (failed(rv)) { await pause(); continue; }
      const client = rv.low >>> 0, ip = addressIP();
      openFDs.add(client);
      try { await nonblocking(client); return { fd: client, ip }; }
      catch (e) { await close(client); throw e; }
    }
  }
  async function receive(fd, ptr, max, deadline) {
    for (;;) {
      await wait(fd, POLLIN, deadline);
      const rv = await sys(SYS.RECVFROM, fd, ptr, max, 0x80, 0, 0);
      if (!failed(rv)) return rv.low >>> 0;
      await pause(); // A readiness race may still produce EAGAIN.
    }
  }
  async function sendAll(fd, ptr, len, network = true) {
    let offset = 0, deadline = Date.now() + timeoutMs;
    while (offset < len) {
      if (network) await wait(fd, POLLOUT, deadline);
      const rv = network
        ? await sys(SYS.SENDTO, fd, ptr.add32(offset), len - offset, 0x20080, 0, 0)
        : await sys(SYS.WRITE, fd, ptr.add32(offset), len - offset);
      if (network && failed(rv)) { await pause(); continue; }
      const n = checked(rv, "write", 451);
      if (n === 0 || n > len - offset) throw new FTPError(451, "Short write made no progress");
      offset += n;
      deadline = Date.now() + timeoutMs;
    }
  }
  async function text(fd, str, ptr = control) {
    const bytes = encoder.encode(str);
    for (let offset = 0; offset < bytes.length; offset += CHUNK) {
      const chunk = bytes.subarray(offset, offset + CHUNK);
      putBytes(ptr, chunk);
      await sendAll(fd, ptr, chunk.length);
    }
  }
  const reply = (code, message) => text(ctrl, `${code} ${message}\r\n`);
  async function closeData() {
    const oldData = data, oldPassive = passive;
    data = passive = null; active = null;
    await close(oldData);
    await close(oldPassive);
  }
  async function connectData() {
    const deadline = Date.now() + timeoutMs;
    if (passive !== null) {
      for (;;) {
        const incoming = await accept(passive, deadline);
        if (incoming.ip.join(".") === peerIP.join(".")) { data = incoming.fd; break; }
        await close(incoming.fd);
      }
      await close(passive); passive = null;
    } else if (active) {
      data = await socket();
      const rv = await sys(SYS.CONNECT, data, sockaddr(active.ip, active.port), 16);
      // An upload client may send and half-close before connect finishes.
      // Readable data/EOF is also evidence that the connection completed.
      if (failed(rv)) await wait(data, POLLIN | POLLOUT, deadline);
      p.write4(optlen, 4); p.write4(opt, 0);
      checked(await sys(SYS.GETSOCKOPT, data, SOL_SOCKET, 0x1007, opt, optlen), "getsockopt", 425);
      if (p.read4(opt) !== 0) throw new FTPError(425, "Active connection failed");
    } else throw new FTPError(425, "Use PASV, EPSV or PORT first");
  }
  async function seek(fd, offset) {
    const want = new api.int64(offset >>> 0, Math.floor(offset / 0x100000000));
    const rv = await sys(SYS.LSEEK, fd, want, 0);
    if ((rv.low >>> 0) !== want.low || (rv.hi >>> 0) !== want.hi)
      throw new FTPError(550, "Could not seek to restart offset");
  }
  async function transfer(command, argument) {
    const offset = restart; restart = null;
    let file = null, started = false;
    try {
      if (passive === null && !active) throw new FTPError(425, "Use PASV, EPSV or PORT first");
      const listing = command === "LIST" || command === "NLST";
      // Common clients send LIST -a or LIST -al. Paths with spaces are retained.
      const listPath = argument.replace(/^-[aAl]+(?:\s+|$)/, "");
      const path = resolvePath(listing ? listPath || cwd : argument);
      if (listing) await resolveWorkerErrno();
      if (listing || command === "RETR") {
        const info = await stat(path);
        if (listing ? !isDir(info) : !isFile(info))
          throw new FTPError(550, listing ? "Not a directory" : "Not a regular file");
        // Open directory read-only; O_NONBLOCK is for file streaming, not directories.
        file = await open(path, 0, !listing);
      } else {
        // Reject devices, FIFOs and directories before opening for upload.
        const existing = await sys(SYS.STAT, pathPtr(path), st);
        if (!failed(existing) && !isFile(statResult())) throw new FTPError(550, "Not a regular file");
        const flags = 1 | 0x200 | (command === "APPE" ? 8 : offset === null ? 0x400 : 0);
        file = await open(path, flags);
      }
      checked(await sys(SYS.FSTAT, file, st), "fstat");
      const opened = statResult();
      if (listing ? !isDir(opened) : !isFile(opened)) throw new FTPError(550, "Invalid file type");
      if (!listing && command !== "APPE" && offset !== null) await seek(file, offset);
      await reply(150, "Opening data connection");
      started = true;
      try { await connectData(); }
      catch (e) { throw new FTPError(425, e.message); }
      if (listing) {
        let useGetdirentries = false;
        let getdentsFailure = "";
        p.write4(dirbase, 0); p.write4(dirbase.add32(4), 0);
        for (;;) {
          let result;
          if (!useGetdirentries) {
            result = await directoryRead(SYS.GETDENTS, file);
            if (failed(result.rv)) {
              getdentsFailure = directoryError(result);
              useGetdirentries = true;
            }
          }
          // PS5 libkernel exports getdirentries, used by BSD readdir. Try getdents
          // first, and fall back to getdirentries on the same fd when it fails.
          if (useGetdirentries) result = await directoryRead(SYS.GETDIRENTRIES, file);
          if (failed(result.rv)) {
            const uid = await sys(SYS.GETUID), sandbox = await sys(SYS.IS_IN_SANDBOX);
            const context = `uid=${failed(uid) ? "unknown" : uid.low >>> 0}, sandbox=${failed(sandbox) ? "unknown" : sandbox.low >>> 0}`;
            const message = `Directory read failed for ${path}: getdents(272)=${getdentsFailure}, getdirentries(196)=${directoryError(result)}; ${context}`;
            await api.log(message, "warn");
            throw new FTPError(451, message);
          }
          const count = result.rv.low >>> 0;
          if (!count) break;
          if (count > DIR_CHUNK) throw new FTPError(451, "Invalid directory read size");
          let cursor = 0;
          while (cursor < count) {
            if (count - cursor < 8) throw new FTPError(451, "Truncated directory entry");
            const entry = dirents.add32(cursor);
            const length = p.read2(entry.add32(4)), namelen = p.read1(entry.add32(7));
            if (length < 8 || length > count - cursor || namelen > length - 8)
              throw new FTPError(451, "Invalid directory entry");
            const filename = decoder.decode(getBytes(entry.add32(8), namelen));
            cursor += length;
            if (filename === "." || filename === ".." || /[\0\r\n/]/.test(filename)) continue;
            if (command === "NLST") { await text(data, filename + "\r\n", io); continue; }
            let info;
            try { info = await stat(resolvePath(filename, path)); }
            catch (e) { if (e instanceof FTPError) continue; throw e; }
            const date = new Date(info.mtime * 1000);
            const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
            const stamp = `${months[date.getUTCMonth()] || "Jan"} ${String(date.getUTCDate() || 1).padStart(2, " ")} ` +
              `${String(date.getUTCHours() || 0).padStart(2, "0")}:${String(date.getUTCMinutes() || 0).padStart(2, "0")}`;
            await text(data, `${permissions(info.mode)} 1 ps5 ps5 ${info.size} ${stamp} ${filename}\r\n`, io);
          }
        }
      } else if (command === "RETR") {
        for (;;) {
          const n = checked(await sys(SYS.READ, file, io, CHUNK), "read", 451);
          if (!n) break;
          if (n > CHUNK) throw new FTPError(451, "Invalid file read size");
          await sendAll(data, io, n);
        }
      } else {
        for (;;) {
          const n = await receive(data, io, CHUNK, Date.now() + timeoutMs);
          if (!n) break;
          if (n > CHUNK) throw new FTPError(451, "Invalid receive size");
          await sendAll(file, io, n, false);
        }
      }
      await close(file); file = null;
      await closeData();
      await reply(226, "Transfer complete");
    } catch (e) {
      await closeData();
      if (!(e instanceof FTPError)) throw e;
      await reply(e.code || (started ? 426 : 550), e.message);
    } finally { await close(file); }
  }
  function permissions(mode) {
    const types = { 0x1000: "p", 0x2000: "c", 0x4000: "d", 0x6000: "b", 0x8000: "-", 0xa000: "l", 0xc000: "s", 0xe000: "w" };
    const chars = (types[mode & 0xf000] || "-") + Array.from({ length: 9 }, (_, i) =>
      mode & (1 << (8 - i)) ? "rwx"[i % 3] : "-").join("");
    const bits = chars.split("");
    if (mode & 0o4000) bits[3] = mode & 0o100 ? "s" : "S";
    if (mode & 0o2000) bits[6] = mode & 0o010 ? "s" : "S";
    if (mode & 0o1000) bits[9] = mode & 0o001 ? "t" : "T";
    return bits.join("");
  }
  const quote = (path) => `"${path.replace(/"/g, '""')}"`;
  async function command(line) {
    const match = /^([A-Za-z]+)(?: +(.*))?$/.exec(line);
    if (!match) throw new FTPError(500, "Invalid command");
    const verb = match[1].toUpperCase(), arg = match[2] || "";
    if (verb !== "RNTO") renameFrom = null;
    switch (verb) {
      case "USER": return reply(331, "Anonymous login accepted; send password");
      case "PASS": return reply(230, "Logged in");
      case "NOOP": return reply(200, "OK");
      case "SYST": return reply(215, "UNIX Type: L8");
      case "FEAT": return text(ctrl, "211-Extensions\r\n REST STREAM\r\n SIZE\r\n MDTM\r\n EPSV\r\n UTF8\r\n211 End\r\n");
      case "OPTS":
        if (/^UTF8 (ON|OFF)$/i.test(arg)) return reply(200, "UTF8 enabled");
        throw new FTPError(501, "Unsupported option");
      case "TYPE":
        if (!/^(I|A|A N|L 8)$/i.test(arg)) throw new FTPError(504, "Unsupported transfer type");
        return reply(200, "Transfer type accepted");
      case "PWD": case "XPWD": return reply(257, `${quote(cwd)} is the current directory`);
      case "CWD": case "XCWD": case "CDUP": case "XCUP": {
        const path = resolvePath(verb === "CDUP" || verb === "XCUP" ? ".." : arg);
        if (!isDir(await stat(path))) throw new FTPError(550, "Not a directory");
        cwd = path; return reply(250, "Directory changed");
      }
      case "PASV": case "EPSV": {
        if (verb === "EPSV" && arg && arg !== "1") throw new FTPError(522, "IPv4 only; use EPSV 1");
        await closeData();
        try {
          passive = await listen(0);
          const picked = await name(passive);
          if (verb === "EPSV") return await reply(229, `Entering Extended Passive Mode (|||${picked.port}|)`);
          const ip = advertisedIP || localIP;
          return await reply(227, `Entering Passive Mode (${ip.join(",")},${picked.port >>> 8},${picked.port & 255})`);
        } catch (e) { await closeData(); throw e; }
      }
      case "PORT": {
        await closeData();
        const pieces = arg.split(",");
        if (pieces.length !== 6 || pieces.some((v) => !/^\d{1,3}$/.test(v) || Number(v) > 255))
          throw new FTPError(501, "Invalid PORT address");
        const nums = pieces.map(Number), ip = nums.slice(0, 4), port = nums[4] * 256 + nums[5];
        if (!port || ip.join(".") !== peerIP.join(".")) throw new FTPError(501, "PORT must use the control peer address");
        active = { ip, port }; return reply(200, "PORT command OK");
      }
      case "LIST": case "NLST": case "RETR": case "STOR": case "APPE":
        return transfer(verb, arg);
      case "REST": {
        if (!/^\d+$/.test(arg) || !Number.isSafeInteger(Number(arg))) throw new FTPError(501, "Invalid restart offset");
        restart = Number(arg); return reply(350, `Restarting at ${restart}`);
      }
      case "SIZE": case "MDTM": {
        const info = await stat(resolvePath(arg));
        if (!isFile(info)) throw new FTPError(550, "Not a regular file");
        if (verb === "SIZE") return reply(213, String(info.size));
        const date = new Date(info.mtime * 1000);
        if (!Number.isFinite(date.getTime())) throw new FTPError(550, "Invalid modification time");
        return reply(213, date.toISOString().slice(0, 19).replace(/[-:T]/g, ""));
      }
      case "MKD": case "XMKD": {
        const path = resolvePath(arg);
        checked(await sys(SYS.MKDIR, pathPtr(path), 0o755), "mkdir");
        return reply(257, `${quote(path)} created`);
      }
      case "RMD": case "XRMD":
        checked(await sys(SYS.RMDIR, pathPtr(resolvePath(arg))), "rmdir");
        return reply(250, "Directory removed");
      case "DELE":
        checked(await sys(SYS.UNLINK, pathPtr(resolvePath(arg))), "unlink");
        return reply(250, "File deleted");
      case "RNFR": {
        const path = resolvePath(arg); await stat(path); renameFrom = path;
        return reply(350, "Send RNTO");
      }
      case "RNTO": {
        const from = renameFrom; renameFrom = null;
        if (!from) throw new FTPError(503, "Send RNFR first");
        const to = resolvePath(arg);
        checked(await sys(SYS.RENAME, pathPtr(from), pathPtr(to, pathB)), "rename");
        return reply(250, "File renamed");
      }
      case "SITE": {
        if (arg.toUpperCase() === "STOP") { stopped = true; await reply(221, "FTP server stopping"); return true; }
        const chmod = /^CHMOD +([0-7]{1,4}) +(.+)$/i.exec(arg);
        if (!chmod) throw new FTPError(501, "Use SITE CHMOD <octal mode> <path> or SITE STOP");
        checked(await sys(SYS.CHMOD, pathPtr(resolvePath(chmod[2])), parseInt(chmod[1], 8)), "chmod");
        return reply(200, "Permissions changed");
      }
      case "ABOR": await closeData(); return reply(226, "No transfer in progress");
      case "QUIT": await reply(221, "Goodbye"); return true;
      default: throw new FTPError(502, "Command not implemented");
    }
  }
  async function session() {
    cwd = resolvePath(options.path, "/"); restart = renameFrom = null;
    if (!isDir(await stat(cwd))) throw new FTPError(550, "Initial path is not a directory");
    localIP = (await name(ctrl)).ip;
    await reply(220, "WebKit Remote Loader FTP Server");
    let pending = "", deadline = Date.now() + timeoutMs;
    for (;;) {
      const n = await receive(ctrl, control, CHUNK, deadline);
      if (!n) return;
      if (n > CHUNK) throw new FTPError(500, "Invalid control receive size");
      pending += controlDecoder.decode(getBytes(control, n), { stream: true });
      let end;
      while ((end = pending.indexOf("\n")) !== -1) {
        const line = pending.slice(0, end).replace(/\r$/, "");
        pending = pending.slice(end + 1);
        if (encoder.encode(line).length > MAX_LINE) throw new FTPError(500, "Command too long");
        try { if (await command(line)) return; }
        catch (e) {
          if (!(e instanceof FTPError)) throw e;
          await reply(e.code, e.message);
        }
        deadline = Date.now() + timeoutMs;
      }
      if (encoder.encode(pending).length > MAX_LINE) throw new FTPError(500, "Command too long");
    }
  }

  for (const [key, nr] of Object.entries(SYS)) {
    if (api.syscalls && !api.syscalls[nr]) throw new Error(`Firmware ${api.fw} is missing ${key} syscall`);
  }
  if (typeof api.setPayloadTimeout !== "function")
    throw new Error("FTP requires a loader with api.setPayloadTimeout; update/re-cache the loader first");
  // No detached tasks: the loader's syscall gate belongs to this payload until
  // all sockets are closed. Disabling the deadline prevents a second accept
  // loop from starting while this long-running service still uses the worker.
  api.setPayloadTimeout(0);
  try {
    cwd = resolvePath(options.path, "/");
    if (!isDir(await stat(cwd))) throw new Error("Initial FTP path is not a directory");
    listener = await listen(options.port);
    await api.log(`FTP listening on port ${options.port}; anonymous login, plain FTP`, "success");
    await api.log("Keep send.py running. QUIT ends the session; SITE STOP stops the server.", "info");
    do {
      const client = await accept(listener, Date.now() + timeoutMs);
      ctrl = client.fd; peerIP = client.ip;
      await api.log(`FTP client connected: ${peerIP.join(".")}`, "info");
      try { await session(); }
      catch (e) {
        if (e instanceof FTPError) {
          try { await reply(421, e.message); } catch {}
          await api.log(`FTP session ended: ${e.message}`, "warn");
        } else throw e;
      } finally {
        controlDecoder.decode(); // Flush UTF-8 decoder state before the next client.
        await closeData(); await close(ctrl); ctrl = null;
      }
    } while (options.persist && !stopped);
  } finally {
    for (const fd of Array.from(openFDs)) {
      try { await close(fd); } catch {}
    }
    for (const mapping of [rawWritable, rawMapping]) {
      if (mapping) {
        try { await sys(SYS.MUNMAP, mapping, RAW_PAGE_SIZE); } catch {}
      }
    }
    await api.log("FTP server closed; remote loader ready for another payload", "info");
  }
};
