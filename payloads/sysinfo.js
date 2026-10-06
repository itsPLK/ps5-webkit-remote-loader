// Inspect credentials, system parameters, and directories.

const SYS_OPEN = 0x005;
const SYS_CLOSE = 0x006;
const SYS_GETPID = 0x014;
const SYS_GETUID = 0x018;
const SYS_GETEUID = 0x019;
const SYS_GETPPID = 0x027;
const SYS_GETEGID = 0x02b;
const SYS_GETGID = 0x02f;
const SYS_NETGETIFLIST = 0x07d;
const SYS___SYSCTL = 0x0ca;
const SYS_GETDIRENTRIES = 0x0c4; // 196
const SYS_GETDENTS = 0x110;       // 272
const SYS_IS_IN_SANDBOX = 0x249;

const O_RDONLY = 0;

// Internal PS5 partitions (/data, /user) use 64 KiB blocks.
const DIR_CHUNK = 0x10000;
const ARENA_SIZE = 0x11000;

// Arena memory layout:
//   +0x00000: dirents buffer (64 KiB)
//   +0x10000: dirbase (8 bytes for getdirentries)
//   +0x10010: sysctl mib (64 bytes)
//   +0x10050: sysctl len (8 bytes)
//   +0x10060: sysctl name input (128 bytes)
//   +0x10100: sysctl data output (768 bytes)

async function nameToMib(api, arena, name) {
  const mibPtr = arena.add32(0x10010);
  const lenPtr = arena.add32(0x10050);
  const namePtr = arena.add32(0x10060);
  const outPtr = arena.add32(0x10100);

  api.p.write4(mibPtr, 0); // CTL_SYSCTL
  api.p.write4(mibPtr.add32(4), 3); // CTL_SYSCTL_NAME2OID
  api.p.write4(lenPtr, 64);
  api.p.write4(lenPtr.add32(4), 0);

  const enc = new TextEncoder();
  const bytes = enc.encode(name);
  for (let i = 0; i < bytes.length; i++) {
    api.p.write1(namePtr.add32(i), bytes[i]);
  }

  const rv = await api.chain.syscall(SYS___SYSCTL, mibPtr, 2, outPtr, lenPtr, namePtr, bytes.length);
  if (api.isFailure(rv) || rv.low !== 0) return null;

  const len = api.p.read4(lenPtr);
  const mib = [];
  for (let i = 0; i < (len >>> 2); i++) {
    mib.push(api.p.read4(outPtr.add32(i * 4)));
  }
  return mib;
}

async function sysctlReadString(api, arena, name) {
  const mib = await nameToMib(api, arena, name);
  if (!mib) return null;

  const mibPtr = arena.add32(0x10010);
  const lenPtr = arena.add32(0x10050);
  const outPtr = arena.add32(0x10100);

  for (let i = 0; i < mib.length; i++) {
    api.p.write4(mibPtr.add32(i * 4), mib[i]);
  }
  api.p.write4(lenPtr, 768);
  api.p.write4(lenPtr.add32(4), 0);

  const rv = await api.chain.syscall(SYS___SYSCTL, mibPtr, mib.length, outPtr, lenPtr, 0, 0);
  if (api.isFailure(rv) || rv.low !== 0) return null;

  const len = api.p.read4(lenPtr);
  let str = "";
  for (let i = 0; i < len; i++) {
    const ch = api.p.read1(outPtr.add32(i));
    if (ch === 0) break;
    str += String.fromCharCode(ch);
  }
  return str.trim();
}

async function sysctlReadInt(api, arena, name) {
  const mib = await nameToMib(api, arena, name);
  if (!mib) return null;

  const mibPtr = arena.add32(0x10010);
  const lenPtr = arena.add32(0x10050);
  const outPtr = arena.add32(0x10100);

  for (let i = 0; i < mib.length; i++) {
    api.p.write4(mibPtr.add32(i * 4), mib[i]);
  }
  api.p.write4(lenPtr, 8);
  api.p.write4(lenPtr.add32(4), 0);

  const rv = await api.chain.syscall(SYS___SYSCTL, mibPtr, mib.length, outPtr, lenPtr, 0, 0);
  if (api.isFailure(rv) || rv.low !== 0) return null;

  const len = api.p.read4(lenPtr);
  if (len >= 8) {
    const low = api.p.read4(outPtr) >>> 0;
    const hi = api.p.read4(outPtr.add32(4)) >>> 0;
    return BigInt(low) + (BigInt(hi) << 32n);
  }
  return api.p.read4(outPtr) >>> 0;
}

async function listDirectory(api, arena, path) {
  const pathPtr = api.p.stringify(path);
  const fd = await api.chain.syscall(SYS_OPEN, pathPtr, O_RDONLY);
  if (api.isFailure(fd)) return null;

  const dirents = arena;
  const dirbase = arena.add32(0x10000);
  api.p.write4(dirbase, 0);
  api.p.write4(dirbase.add32(4), 0);

  const entries = [];
  let useGetdirentries = false;

  try {
    for (;;) {
      let res;
      if (!useGetdirentries) {
        res = await api.chain.syscall(SYS_GETDENTS, fd, dirents, DIR_CHUNK);
        if (api.isFailure(res)) {
          useGetdirentries = true;
        }
      }
      if (useGetdirentries) {
        res = await api.chain.syscall(SYS_GETDIRENTRIES, fd, dirents, DIR_CHUNK, dirbase);
      }
      if (api.isFailure(res)) break;

      const count = res.low >>> 0;
      if (count === 0) break;

      let cursor = 0;
      while (cursor < count) {
        if (count - cursor < 8) break;
        const entry = dirents.add32(cursor);
        const reclen = api.p.read2(entry.add32(4));
        const type = api.p.read1(entry.add32(6));
        const namelen = api.p.read1(entry.add32(7));
        if (reclen < 8 || reclen > count - cursor || namelen > reclen - 8) break;

        let name = "";
        for (let i = 0; i < namelen; i++) {
          name += String.fromCharCode(api.p.read1(entry.add32(8 + i)));
        }
        cursor += reclen;

        if (name === "." || name === "..") continue;
        entries.push({ name, type });
      }
    }
  } finally {
    await api.chain.syscall(SYS_CLOSE, fd);
  }

  entries.sort((a, b) => a.name.localeCompare(b.name));
  return entries;
}

function fmtPtr(ptr) {
  return ptr ? `0x${ptr.toString(16)}` : "(unresolved)";
}

return async function (api) {
  await api.log("=== System & Firmware ===", "info");
  await api.log(`Firmware:       ${api.fw || "unknown"}`);
  await api.log(`Kernel R/W:     ${api.krw ? "established (active)" : "not established"}`);

  // Reusable arena for sysctl queries and 64 KiB directory readings
  const arena = api.p.malloc(ARENA_SIZE, 1);
  const ostype = await sysctlReadString(api, arena, "kern.ostype");
  const osrelease = await sysctlReadString(api, arena, "kern.osrelease");
  if (ostype || osrelease) {
    await api.log(`OS:             ${[ostype, osrelease].filter(Boolean).join(" ")}`);
  }
  const hwModel = await sysctlReadString(api, arena, "hw.model");
  if (hwModel) await api.log(`Hardware:       ${hwModel}`);

  const ncpu = await sysctlReadInt(api, arena, "hw.ncpu");
  if (ncpu != null) await api.log(`CPU Cores:      ${ncpu}`);

  const physmem = await sysctlReadInt(api, arena, "hw.physmem");
  if (physmem != null) {
    const bytes = typeof physmem === "bigint" ? physmem : BigInt(physmem);
    const mb = Number(bytes / (1024n * 1024n));
    await api.log(`Physical RAM:   ${mb} MB`);
  }

  await api.log("=== Process Identity ===", "info");
  const pid = (await api.chain.syscall(SYS_GETPID)).low >>> 0;
  const ppid = (await api.chain.syscall(SYS_GETPPID)).low >>> 0;
  await api.log(`PID / PPID:     ${pid} / ${ppid}`);

  const uid = (await api.chain.syscall(SYS_GETUID)).low >>> 0;
  const euid = (await api.chain.syscall(SYS_GETEUID)).low >>> 0;
  await api.log(`UID / EUID:     ${uid}${uid === 0 ? " (root)" : ""} / ${euid}`);

  const gid = (await api.chain.syscall(SYS_GETGID)).low >>> 0;
  const egid = (await api.chain.syscall(SYS_GETEGID)).low >>> 0;
  await api.log(`GID / EGID:     ${gid} / ${egid}`);

  const sbox = await api.chain.syscall(SYS_IS_IN_SANDBOX);
  let sandboxStatus = "unknown";
  if (!api.isFailure(sbox)) {
    sandboxStatus = sbox.low === 0 ? "escaped (unsandboxed)" : "active (restricted)";
  }
  await api.log(`Sandbox:        ${sandboxStatus}`);

  await api.log("=== Memory Map ===", "info");
  await api.log(`libkernel:      ${fmtPtr(api.libKernelBase)}`);
  await api.log(`libSceNKWebKit: ${fmtPtr(api.libSceNKWebKitBase)}`);
  await api.log(`libSceLibc:     ${fmtPtr(api.libSceLibcInternalBase)}`);

  // Query network interfaces
  const ifCountRes = await api.chain.syscall(SYS_NETGETIFLIST, 0, 10);
  if (!api.isFailure(ifCountRes)) {
    const ifCount = ifCountRes.low | 0;
    if (ifCount > 0 && ifCount <= 32) {
      const RECORD = 0x3c0;
      const list = api.p.malloc(RECORD * ifCount, 1);
      const rv = await api.chain.syscall(SYS_NETGETIFLIST, list, ifCount);
      if (!api.isFailure(rv)) {
        await api.log("=== Network Interfaces ===", "info");
        for (let i = 0; i < ifCount; i++) {
          let name = "";
          for (let c = 0; c < 16; c++) {
            const ch = api.p.read1(list.add32(RECORD * i + c));
            if (ch === 0) break;
            name += String.fromCharCode(ch);
          }
          const octets = [0, 1, 2, 3].map((b) => api.p.read1(list.add32(RECORD * i + 40 + b)));
          const ip = octets.join(".");
          if (name.length > 0) {
            await api.log(`  ${(name + ":").padEnd(12, " ")} ${ip === "0.0.0.0" ? "(no ip)" : ip}`);
          }
        }
      }
    }
  }

  // Directory listings (defaults to root /, plus any paths passed in argv)
  const targetDirs = ["/"];
  if (api.args && api.args.length > 0) {
    for (const arg of api.args) {
      if (!targetDirs.includes(arg)) targetDirs.push(arg);
    }
  }

  for (const dir of targetDirs) {
    await api.log(`=== Directory Listing: ${dir} ===`, "info");
    const entries = await listDirectory(api, arena, dir);
    if (!entries) {
      await api.log("  (denied or not found)", "warn");
      continue;
    }
    if (entries.length === 0) {
      await api.log("  (empty)");
      continue;
    }
    for (const item of entries) {
      const isDir = item.type === 4;
      const typeLabel = isDir ? "[dir]" : item.type === 8 ? "[file]" : item.type === 10 ? "[link]" : "";
      const displayName = isDir ? `${item.name}/` : item.name;
      await api.log(`  ${displayName.padEnd(24, " ")} ${typeLabel}`);
    }
  }
};
